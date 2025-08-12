use heck::AsUpperCamelCase;
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    Attribute, Error, Expr, FnArg, Ident, ItemFn, ItemImpl, Meta, Pat, PatIdent, Result, Token,
    Type,
    parse::{Parse, ParseStream},
    parse_macro_input, parse_quote,
    punctuated::Punctuated,
};

#[proc_macro_attribute]
pub fn syscall(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attrs as SyscallAttr);
    let input = parse_macro_input!(input as ItemFn);

    expand_syscall(attrs, input).map_or_else(|a| Error::into_compile_error(a).into(), Into::into)
}

fn expand_syscall(attr: SyscallAttr, mut input: ItemFn) -> Result<impl Into<TokenStream>> {
    let syscall_inputs = collect_syscall_inputs(input.clone())?;

    // Remove `#[state]` attribute for parameters.
    input.sig.inputs.iter_mut().for_each(|input| {
        let FnArg::Typed(t) = input else {
            return;
        };
        t.attrs.retain(|a| !is_state_attr(a));
    });

    let syscall_ident = &input.sig.ident;
    let syscall_name = syscall_ident.to_string();
    let struct_name = format!("Sys{}", AsUpperCamelCase(&syscall_name));
    let struct_ident = Ident::new(&struct_name, input.sig.ident.span());
    let state_bindings = syscall_inputs.states.iter().map(|(pat, ty)| {
        let mut pat = pat.clone();
        pat.mutability.take();
        quote! {
            let #pat = <#ty as ExtractableThreadState>::extract_from_thread(&guard);
        }
    });
    let arg_bindings = syscall_inputs
        .args
        .iter()
        .enumerate()
        .map(|(idx, (pat, ty))| {
            quote! {
                let #pat = <#ty as SyscallArg>::parse(syscall_args.args[#idx], abi)?;
            }
        });
    let print_statements = syscall_inputs
        .args
        .iter()
        .enumerate()
        .map(|(idx, (pat, ty))| {
            let arg_name = &pat.ident;
            let format_string = if idx == 0 {
                format!("{arg_name}=")
            } else {
                format!(", {arg_name}=")
            };
            quote! {
                write!(f, #format_string)?;
                <#ty as SyscallArg>::display(f, syscall_args.args[#idx], abi, thread)?;
            }
        });
    let function_invocation_args = input
        .sig
        .inputs
        .iter()
        .map(|input| match input {
            FnArg::Receiver(_) => {
                unreachable!("this should have already been checked in collect_syscall_args")
            }
            FnArg::Typed(arg) => arg,
        })
        .map(|pat| match &*pat.pat {
            Pat::Ident(ident) => &ident.ident,
            _ => unreachable!("this should have already been checked in collect_syscall_args"),
        });

    // Make sure that syscall arguments don't get marked as unused.
    for (i, (ident, _)) in syscall_inputs.args.iter().enumerate() {
        input.block.stmts.insert(
            i,
            parse_quote! {
                let _ = #ident;
            },
        );
    }
    // Make sure that clippy doesn't warn about the number of arguments.
    input
        .attrs
        .push(parse_quote! {#[allow(clippy::too_many_arguments)]});

    let future = if input.sig.asyncness.is_some() {
        let mut future = quote! {
            #syscall_ident(#(#function_invocation_args),*)
        };
        if attr.interruptable {
            let restartable = attr.restartable;
            future = quote! {
                async move {
                    thread.clone().interruptable(#future, #restartable).await
                }
            };
        }
        future
    } else {
        if attr.interruptable {
            return Err(Error::new(
                Span::call_site(),
                "non-async syscalls cannot be interrupted",
            ));
        }

        let needs_thread = input.sig.inputs.iter().any(|arg| match arg {
            FnArg::Receiver(_) => false,
            FnArg::Typed(t) => match &*t.pat {
                Pat::Ident(ident) => ident.ident == "thread",
                _ => false,
            },
        });
        let thread = needs_thread.then(|| {
            quote! {
                let thread = ThreadArg::get(&thread);
            }
        });

        quote! {
            async move {
                #thread
                #syscall_ident(#(#function_invocation_args),*)
            }
        }
    };

    let i386 = if let Some(i386) = attr.i386 {
        quote! { Some(#i386) }
    } else {
        quote! { None }
    };
    let amd64 = if let Some(amd64) = attr.amd64 {
        quote! { Some(#amd64) }
    } else {
        quote! { None }
    };

    Ok(quote! {
        #input

        struct #struct_ident;

        impl Syscall for #struct_ident {
            const NO_I386: Option<usize> = #i386;
            const NO_AMD64: Option<usize> = #amd64;

            async fn execute(
                thread: &Arc<Thread>,
                syscall_args: SyscallArgs,
            ) -> SyscallResult {
                let abi = syscall_args.abi;

                let guard = thread.lock();
                #(#state_bindings)*
                drop(guard);

                #(#arg_bindings)*

                let future = #future;
                future.await
            }
            fn display(
                f: &mut dyn fmt::Write,
                syscall_args: SyscallArgs,
                thread: &ThreadGuard<'_>,
            ) -> fmt::Result {
                let abi = syscall_args.abi;

                write!(f, "{}(", #syscall_name)?;
                #(#print_statements)*
                write!(f, ")")
            }
        }
    })
}

struct SyscallAttr {
    i386: Option<Expr>,
    amd64: Option<Expr>,
    interruptable: bool,
    restartable: bool,
}

impl Parse for SyscallAttr {
    fn parse(input: ParseStream) -> Result<Self> {
        let vars = Punctuated::<Meta, Token![,]>::parse_terminated(input)?;

        let mut i386 = None;
        let mut amd64 = None;
        let mut interruptable = false;
        let mut restartable = false;
        for var in vars.iter() {
            if var.path().is_ident("amd64") {
                let name_value = var.require_name_value()?;
                if amd64.is_some() {
                    return Err(Error::new_spanned(name_value, "duplicate amd64"));
                }
                amd64 = Some(name_value.value.clone());
            } else if var.path().is_ident("i386") {
                let name_value = var.require_name_value()?;
                if i386.is_some() {
                    return Err(Error::new_spanned(name_value, "duplicate i386"));
                }
                i386 = Some(name_value.value.clone());
            } else if var.path().is_ident("interruptable") {
                let name_value = var.require_path_only()?;
                if interruptable {
                    return Err(Error::new_spanned(name_value, "duplicate interruptable"));
                }
                interruptable = true;
            } else if var.path().is_ident("restartable") {
                let name_value = var.require_path_only()?;
                if restartable {
                    return Err(Error::new_spanned(name_value, "duplicate restartable"));
                }
                restartable = true;
            } else {
                return Err(Error::new_spanned(var.path(), "invalid attribute"));
            }
        }

        Ok(Self {
            i386,
            amd64,
            interruptable,
            restartable,
        })
    }
}

fn collect_syscall_inputs(item: ItemFn) -> Result<SyscallInputs> {
    let inputs = item
        .sig
        .inputs
        .into_iter()
        .map(|a| match a {
            FnArg::Receiver(receiver) => {
                Err(Error::new_spanned(receiver, "unexpected receiver input"))
            }
            FnArg::Typed(typed) => Ok(typed),
        })
        .collect::<Result<Vec<_>>>()?;
    let args = inputs
        .into_iter()
        .map(|a| match *a.pat {
            Pat::Ident(pat) => Ok((a.attrs, pat, *a.ty)),
            other => Err(Error::new_spanned(
                other,
                "only ident patterns are supported",
            )),
        })
        .collect::<Result<Vec<_>>>()?;

    let mut inputs = SyscallInputs {
        states: Vec::new(),
        args: Vec::new(),
    };

    for (attrs, pat, ty) in args {
        if pat.ident == "thread" || pat.ident == "abi" {
            continue;
        }

        if attrs.iter().any(is_state_attr) {
            inputs.states.push((pat, ty));
        } else {
            inputs.args.push((pat, ty));
        }
    }

    Ok(inputs)
}

fn is_state_attr(attr: &Attribute) -> bool {
    attr.meta.path().is_ident("state")
}

struct SyscallInputs {
    states: Vec<(PatIdent, Type)>,
    args: Vec<(PatIdent, Type)>,
}

#[proc_macro_attribute]
pub fn register(_attrs: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemImpl);
    expand_register(input).map_or_else(|a| Error::into_compile_error(a).into(), Into::into)
}

fn expand_register(input: ItemImpl) -> Result<impl Into<TokenStream>> {
    let ty = &input.self_ty;

    let (_, trait_, _) = input.trait_.as_ref().ok_or_else(|| {
        Error::new_spanned(&input, "only trait implementations can be registered")
    })?;
    let module = if trait_.is_ident("CharDev") {
        quote! {
            crate::char_dev
        }
    } else {
        return Err(Error::new_spanned(trait_, "unsupported trait"));
    };

    Ok(quote! {
        #input

        const _: () = {
            #[::linkme::distributed_slice(#module::REGISTRATIONS)]
            static REGISTRATION: #module::Registration = #module::Registration::new::<#ty>();
        };
    })
}

use heck::AsUpperCamelCase;
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, parse_quote,
    punctuated::Punctuated,
    Attribute, Error, Expr, FnArg, Ident, ItemFn, Meta, Pat, PatIdent, Result, Token, Type,
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
                <#ty as SyscallArg>::display(f, syscall_args.args[#idx], abi, thread, vm_activator)?;
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
        quote! {
            #syscall_ident(#(#function_invocation_args),*)
        }
    } else {
        quote! {
            VirtualMemoryActivator::r#do(move |vm_activator| {
                let mut thread = thread.lock();
                let thread = &mut thread;
                #syscall_ident(#(#function_invocation_args),*)
            })
        }
    };

    let i386 = if let Some(i386) = attr.v {
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
            const NAME: &'static str = #syscall_name;

            async fn execute(
                thread: Arc<Thread>,
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
                vm_activator: &mut VirtualMemoryActivator,
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
    v: Option<Expr>,
    amd64: Option<Expr>,
}

impl Parse for SyscallAttr {
    fn parse(input: ParseStream) -> Result<Self> {
        let vars = Punctuated::<Meta, Token![,]>::parse_terminated(input)?;

        let mut i386 = None;
        let mut amd64 = None;
        for var in vars.iter() {
            let name_value = var.require_name_value()?;
            if name_value.path.is_ident("amd64") {
                if amd64.is_some() {
                    return Err(Error::new_spanned(name_value, "duplicate amd64"));
                }
                amd64 = Some(name_value.value.clone());
            } else if name_value.path.is_ident("i386") {
                if i386.is_some() {
                    return Err(Error::new_spanned(name_value, "duplicate i386"));
                }
                i386 = Some(name_value.value.clone());
            } else {
                return Err(Error::new_spanned(&name_value.path, "invalid attribute"));
            }
        }

        Ok(Self { v: i386, amd64 })
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
        if pat.ident == "thread" || pat.ident == "vm_activator" || pat.ident == "abi" {
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

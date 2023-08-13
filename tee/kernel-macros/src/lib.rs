use heck::AsUpperCamelCase;
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, parse_quote,
    punctuated::Punctuated,
    Error, Expr, FnArg, Ident, ItemFn, Meta, Pat, PatIdent, Result, Token, Type,
};

#[proc_macro_attribute]
pub fn syscall(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attrs as SyscallAttr);
    let input = parse_macro_input!(input as ItemFn);

    expand_syscall(attrs, input).map_or_else(|a| Error::into_compile_error(a).into(), Into::into)
}

fn expand_syscall(
    SyscallAttr { i386, amd64 }: SyscallAttr,
    mut input: ItemFn,
) -> Result<impl Into<TokenStream>> {
    let syscall_args = collect_syscall_args(input.clone())?;

    let syscall_ident = &input.sig.ident;
    let syscall_name = syscall_ident.to_string();
    let struct_name = format!("Sys{}", AsUpperCamelCase(&syscall_name));
    let struct_ident = Ident::new(&struct_name, input.sig.ident.span());
    let bindings = syscall_args.iter().enumerate().map(|(idx, (pat, ty))| {
        quote! {
            let #pat = <#ty as SyscallArg>::parse(syscall_args.args[#idx])?;
        }
    });
    let print_statements = syscall_args.iter().enumerate().map(|(idx, (pat, ty))| {
        let arg_name = &pat.ident;
        let format_string = if idx == 0 {
            format!("{arg_name}=")
        } else {
            format!(", {arg_name}=")
        };
        quote! {
            write!(f, #format_string)?;
            <#ty as SyscallArg>::display(f, syscall_args.args[#idx], thread, vm_activator)?;
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
    for (i, (ident, _)) in syscall_args.iter().enumerate() {
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

    Ok(quote! {
        #input

        struct #struct_ident;

        impl Syscall for #struct_ident {
            const NO_I386: usize = #i386;
            const NO_AMD64: usize = #amd64;
            const NAME: &'static str = #syscall_name;

            async fn execute(
                thread: Arc<Thread>,
                syscall_args: SyscallArgs,
            ) -> SyscallResult {
                #(#bindings)*
                let future = #future;
                future.await
            }
            fn display(
                f: &mut dyn fmt::Write,
                syscall_args: SyscallArgs,
                thread: &ThreadGuard<'_>,
                vm_activator: &mut VirtualMemoryActivator,
            ) -> fmt::Result {
                write!(f, "{}(", #syscall_name)?;
                #(#print_statements)*
                write!(f, ")")
            }
        }
    })
}

struct SyscallAttr {
    i386: Expr,
    amd64: Expr,
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

        let i386 = i386.ok_or_else(|| Error::new_spanned(&vars, "missing `i386` attribute"))?;
        let amd64 = amd64.ok_or_else(|| Error::new_spanned(&vars, "missing `amd64` attribute"))?;

        Ok(Self { i386, amd64 })
    }
}

fn collect_syscall_args(item: ItemFn) -> Result<Vec<(PatIdent, Type)>> {
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
            Pat::Ident(b) => Ok((b, *a.ty)),
            other => Err(Error::new_spanned(
                other,
                "only ident patterns are supported",
            )),
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(args
        .into_iter()
        .filter(|(a, _)| a.ident != "thread" && a.ident != "vm_activator")
        .collect())
}

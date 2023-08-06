use heck::AsUpperCamelCase;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
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
    SyscallAttr { no }: SyscallAttr,
    mut input: ItemFn,
) -> Result<impl Into<TokenStream>> {
    let syscall_args = collect_syscall_args(input.clone())?;

    let syscall_ident = &input.sig.ident;
    let syscall_name = syscall_ident.to_string();
    let struct_name = format!("Sys{}", AsUpperCamelCase(&syscall_name));
    let struct_ident = Ident::new(&struct_name, input.sig.ident.span());
    let trait_name = format_ident!("Syscall{}", syscall_args.len());
    let arg_associated_items = syscall_args.iter().enumerate().map(|(i, (pat, ty))| {
        let arg_name = pat.ident.to_string();
        let assoc_type_ident = format_ident!("Arg{i}");
        let assoc_const_ident = format_ident!("ARG{i}_NAME");
        quote! {
            type #assoc_type_ident = #ty;
            const #assoc_const_ident: &'static str = #arg_name;
        }
    });
    let function_decl_params = syscall_args.iter().map(|(pat, ty)| {
        quote! {
            #pat: #ty
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

        impl #trait_name for #struct_ident {
            const NO: usize = #no;
            const NAME: &'static str = #syscall_name;

            #(#arg_associated_items)*

            async fn execute(
                thread: Arc<Thread>,
                #(#function_decl_params,)*
            ) -> SyscallResult {
                let future = #future;
                future.await
            }
        }
    })
}

struct SyscallAttr {
    no: Expr,
}

impl Parse for SyscallAttr {
    fn parse(input: ParseStream) -> Result<Self> {
        let vars = Punctuated::<Meta, Token![,]>::parse_terminated(input)?;

        let mut no = None;
        for var in vars.iter() {
            let name_value = var.require_name_value()?;
            if name_value.path.is_ident("no") {
                if no.is_some() {
                    return Err(Error::new_spanned(name_value, "duplicate no"));
                }
                no = Some(name_value.value.clone());
            } else {
                return Err(Error::new_spanned(&name_value.path, "invalid attribute"));
            }
        }

        let no = no.ok_or_else(|| Error::new_spanned(&vars, "missing `no` attribute"))?;

        Ok(Self { no })
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

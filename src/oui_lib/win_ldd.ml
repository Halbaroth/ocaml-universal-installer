(**************************************************************************)
(*                                                                        *)
(*    Copyright 2026 OCamlPro                                             *)
(*                                                                        *)
(*  All rights reserved. This file is distributed under the terms of the  *)
(*  GNU Lesser General Public License version 2.1, with the special       *)
(*  exception on linking described in the file LICENSE.                   *)
(*                                                                        *)
(**************************************************************************)

type debugger
type addr

type dll_event =
  | Load of addr
  | Unload of addr

external start_debugger : string -> debugger = "ml_start_debugger"
external wait_dll_event : debugger -> dll_event option = "ml_wait_dll_event"
external get_dll_filename : debugger -> addr -> string = "ml_get_dll_filename"

exception Error of string

let () = Callback.register_exception "Win_ldd.Error" (Error "dummy")

external get_windows_directory : unit -> string = "ml_get_windows_directory"

let is_system32 =
  (* Note: guaranteed to end with '\' *)
  let win_dir = get_windows_directory () in
  fun path ->
    let prefix =
      try String.sub path 0 (String.length win_dir)
      with Invalid_argument _ -> ""
    in
    String.equal prefix win_dir &&
    let suffix =
      try String.sub path (String.length win_dir)
            (String.length path - String.length win_dir)
      with Invalid_argument _ -> ""
    in
    match String.split_on_char '\\' suffix with
    | directory :: _ ->
      String.lowercase_ascii directory = "system32"
      || String.lowercase_ascii directory = "syswow64"
    | _ -> false

external report_dlls : string -> unit = "ml_report_dlls"

let report_dlls s =
  report_dlls s; []

let get_dlls binary =
  let binary = OpamFilename.to_string binary in
  Format.eprintf "Searching dlls of %s...@." binary;
  match report_dlls binary with
  | exception Error msg ->
      Format.eprintf "Failed with the following error: %s" msg;
      []
  | exception _ -> []
  | dlls ->
    List.filter_map (fun dll ->
      if is_system32 dll then None
      else
        let path = OpamFilename.of_string @@ System.normalize_path dll in
        Some path) dlls

let get_dlls binary =
  let binary = OpamFilename.to_string binary in
  let d = start_debugger binary in
  let dlls : (addr, unit) Hashtbl.t = Hashtbl.create 17 in
  let rec loop () =
    match wait_dll_event d with
    | Some (Load addr) -> (
        Format.eprintf "load dll";
        Hashtbl.replace dlls addr ();
        loop ())
    | Some (Unload addr) -> (
        Format.eprintf "unload dll";
        Hashtbl.remove dlls addr;
        loop ())
    | None -> (
        let dlls = List.of_seq @@ Seq.map fst @@ Hashtbl.to_seq dlls in
        List.filter_map (fun addr ->
          let path = get_dll_filename d addr in
          if is_system32 path then None
          else
            let path = OpamFilename.of_string @@ System.normalize_path path in
            Some path) dlls)
  in
  loop ()

(**************************************************************************)
(*                                                                        *)
(*    Copyright 2026 OCamlPro                                             *)
(*                                                                        *)
(*  All rights reserved. This file is distributed under the terms of the  *)
(*  GNU Lesser General Public License version 2.1, with the special       *)
(*  exception on linking described in the file LICENSE.                   *)
(*                                                                        *)
(**************************************************************************)

module DebugEvent : sig
  type dll

  type event =
    | Unknown
    | CreateProcess
    | ExitProcess
    | LoadDll of dll
    | UnloadDll of dll
    | Exception of int

  val trace : string -> unit -> t
end = struct
  type dll
  type process

  type event =
    | Unknown
    | CreateProcess
    | ExitProcess
    | EntryPoint
    | LoadDll of dll
    | UnloadDll of dll
    | Exception of int

  external start_process : string -> process = "ml_start_process"
  (* external stop_process : process -> unit = "ml_stop_process" *)
  external next_debug_event : process -> unit -> t = "ml_next_debug_event"

  let trace path =
    let p = start_process path in
    next_debug_event process
end

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

(* external report_dlls : string -> string list = "ml_report_dlls" *)

let get_dlls binary =
  let binary = OpamFilename.to_string binary in
  Format.eprintf "Searching dlls of %s...@." binary;
  let t = trace binary in
  let rec loop () =
    let () =
      match t () with
      | Unknown ->  Format.eprintf "Unknown@."
      | CreateProcess -> Format.eprintf "CreateProcess@."
      | ExitProcess -> Format.eprintf "ExitProcess@."
      | LoadDll _ -> Format.eprintf "LoadDll@."
      | UnloadDll _ -> Format.eprintf "UnloadDll@."
      | Exception _  -> Format.eprintf "exception@."
    in
    loop ()
  in
  loop ();
  []
  (* match report_dlls binary with *)
  (* | exception Error msg -> *)
  (*     Format.eprintf "Failed with the following error: %s" msg; *)
  (*     [] *)
  (* | exception _ -> [] *)
  (* | dlls -> *)
  (*   List.filter_map (fun dll -> *)
  (*     if is_system32 dll then None *)
  (*     else *)
  (*       let path = OpamFilename.of_string @@ System.normalize_path dll in *)
  (*       Some path) dlls *)

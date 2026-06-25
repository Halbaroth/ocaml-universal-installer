(**************************************************************************)
(*                                                                        *)
(*    Copyright 2026 OCamlPro                                             *)
(*                                                                        *)
(*  All rights reserved. This file is distributed under the terms of the  *)
(*  GNU Lesser General Public License version 2.1, with the special       *)
(*  exception on linking described in the file LICENSE.                   *)
(*                                                                        *)
(**************************************************************************)

exception Error of string

let () = Callback.register_exception "Win_ldd.Error" (Error "dummy")

module Process : sig
  type t

  val start : string -> t
  val close : t -> unit
end = struct
  type t

  external start : string -> t = "ml_process_start"
  external close : t -> unit = "ml_process_stop"
end

module Dll : sig
  type t

  val close : t -> unit
  val filename : Process.t -> t -> string
end = struct
  type t

  external close : t -> unit = "ml_dll_close"
  external filename : Process.t -> t -> string = "ml_dll_filename"
end

module DebugEvent : sig
  type t =
    | Unknown
    | CreateProcess
    | ExitProcess
    | LoadDll of Dll.t
    | UnloadDll of Dll.t
    | Exception of int

  val wait : Process.t -> unit -> t
end = struct
  type t =
    | Unknown
    | CreateProcess
    | ExitProcess
    | LoadDll of Dll.t
    | UnloadDll of Dll.t
    | Exception of int

  external wait : Process.t -> unit -> t = "ml_debugevent_wait"
end

external get_windows_directory : unit -> string = "ml_get_windows_directory"

let _is_system32 =
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
  let p = Process.start binary in
  let t = DebugEvent.wait p in
  let rec loop () : unit =
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

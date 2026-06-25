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

let get_dlls binary =
  let binary = OpamFilename.to_string binary in
  Format.eprintf "Searching dlls of %s...@." binary;
  let dlls : (Dll.t, unit) Hashtbl.t = Hashtbl.create 17 in
  let p = Process.start binary in
  let wait_event = DebugEvent.wait p in
  let rec loop () : unit =
    match wait_event () with
    | Unknown | CreateProcess -> loop ()
    | ExitProcess -> assert false
    | LoadDll dll ->  (
      Hashtbl.replace dlls dll ();
      loop ())
    | UnloadDll dll -> (
      Hashtbl.remove dlls dll;
      loop ())
    | Exception _  ->
      Format.eprintf "exception@."
  in
  loop ();
  let res =
    Hashtbl.to_seq dlls
    |> List.of_seq
    |> List.filter_map (fun (dll, ()) ->
      let path = Dll.filename p dll in
      if is_system32 path then None
      else
        let p = OpamFilename.of_string @@ System.normalize_path path in
        Format.eprintf "Found %s@." path;
        Some p)
  in
  (* Hashtbl.iter (fun dll () -> Dll.close dll) dlls; *)
  (* Process.close p; *)
  res

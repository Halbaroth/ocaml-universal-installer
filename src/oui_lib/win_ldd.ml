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

type process
external start_process : string -> process = "ml_start_process"

type dll
external close_dll : dll -> unit = "ml_close_dll"
external filename_dll : process -> dll -> string = "ml_filename_dll"

type exn =
  | Unknown
  | Breakpoint

type t =
  | Unknown
  | CreateProcess
  | ExitProcess
  | LoadDll of dll
  | UnloadDll of dll
  | Exception of exn

external wait_debug_event : process -> unit -> t = "ml_wait_debug_event"
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
  let dlls : (dll, unit) Hashtbl.t = Hashtbl.create 17 in
  let p = start_process binary in
  let rec loop acc =
    match wait_debug_event p () with
    | ExitProcess -> acc
    | LoadDll dll ->  (
      Hashtbl.replace dlls dll ();
      loop acc)
    | UnloadDll dll -> (
      Hashtbl.remove dlls dll;
      loop acc)
    | Exception Breakpoint ->
      Format.eprintf "Breakpoint!@.";
      let dlls = List.of_seq @@ Hashtbl.to_seq dlls in
      List.filter_map (fun (dll, ()) ->
        match filename_dll p dll with
        | exception _ -> None
        | path ->
          if is_system32 path then None
          else
            let p = OpamFilename.of_string @@ System.normalize_path path in
            Format.eprintf "Found %s@." path;
            Some p) dlls
    | Unknown | CreateProcess | Exception _ -> loop acc
  in
  let res = loop [] in
  Hashtbl.iter (fun dll () -> close_dll dll) dlls;
  res

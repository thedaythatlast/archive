

Experiment 1: I created target.exe using DEBUG_ONLY_THIS_PROCESS, received the initial CREATE_PROCESS_DEBUG_EVENT, did not call ContinueDebugEvent, called TerminateProcess(..., 123), and observed WAIT_OBJECT_0 plus final exit code 123.

Experiment 2: I called TerminateProcess while the create event was pending, then continued the event. I subsequently received and continued LOAD_DLL_DEBUG_EVENT and EXIT_PROCESS_DEBUG_EVENT. The exit event reported 123; afterward the retained process handle was signaled and GetExitCodeProcess returned 123.

Instrumented experiment: The target contained a TLS callback that created tls_callback_ran.txt, an imported DLL whose DllMain(DLL_PROCESS_ATTACH) created dllmain_ran.txt, and main() that created main_ran.txt. Old markers were deleted before the run. None of the markers existed afterward, although process termination completed and the exit code was 123.

Treat these only as observations on the tested system. Marker absence is consistent with the instrumented routines not running, but does not prove that no user-mode instruction whatsoever executed. LOAD_DLL_DEBUG_EVENT must not be treated as proof that DllMain ran.

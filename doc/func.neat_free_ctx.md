## neat_free_ctx
```c
void neat_free_ctx(
    struct neat_ctx *nc);
```
Free any resource used by the context.
Loop must be stopped by `neat_stop_event_loop()` before this function is called.

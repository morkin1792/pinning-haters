package kotlin.jvm.functions;

/** Stand-in for the Kotlin stdlib interface so the fixture compiles without Kotlin. */
public interface Function0<R> {
    R invoke();
}

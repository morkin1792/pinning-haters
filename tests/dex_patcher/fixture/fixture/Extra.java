package fixture;

/** Shapes for the replacement kinds and failure paths the production table does not exercise. */
public abstract class Extra {
    public boolean flag(String s) {
        return s.isEmpty();
    }

    public abstract void abstractCheck(String s);

    public static native int nativeCheck(String s);
}

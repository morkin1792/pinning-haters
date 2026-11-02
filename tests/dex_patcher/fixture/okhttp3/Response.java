package okhttp3;

/** Stand-in for okhttp3.Response. */
public final class Response {
    public final int code;

    public Response(int code) {
        this.code = code;
    }
}

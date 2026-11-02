package okhttp3;

/** Stand-in for okhttp3.Request. */
public final class Request {
    public final String url;

    public Request(String url) {
        this.url = url;
    }
}

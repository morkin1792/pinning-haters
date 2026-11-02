package okhttp3;

import java.io.IOException;

/** Stand-in for okhttp3.Interceptor with the two Chain methods the pass-through template calls. */
public interface Interceptor {
    Response intercept(Chain chain) throws IOException;

    interface Chain {
        Request request();

        Response proceed(Request request) throws IOException;
    }
}

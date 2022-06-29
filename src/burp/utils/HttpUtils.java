//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.utils;

import java.util.Calendar;
import okhttp3.CacheControl;
import okhttp3.CacheControl.Builder;

public class HttpUtils {
    public static CacheControl NoCache = (new Builder()).noCache().noStore().build();

    public HttpUtils() {
    }

    public static okhttp3.Request.Builder GetDefaultRequest(String url) {
        int fakeFirefoxVersion = Utils.GetRandomNumber(45, 94 + Calendar.getInstance().get(1) - 2021);
        okhttp3.Request.Builder requestBuilder = (new okhttp3.Request.Builder()).url(url);
        requestBuilder.header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + fakeFirefoxVersion + ".0) Gecko/20100101 Firefox/" + fakeFirefoxVersion + ".0");
        return requestBuilder.cacheControl(NoCache);
    }


}

package burp.Listen;
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//


import burp.BurpExtender;
import burp.utils.HttpUtils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;
import okhttp3.Response;

public class Ceye {
    OkHttpClient client;
    String platformUrl;
    String rootDomain;
    String token;


    public Ceye() {
        this.client = (new OkHttpClient()).newBuilder().connectTimeout(3000L, TimeUnit.SECONDS).callTimeout(3000L, TimeUnit.SECONDS).build();
        this.platformUrl = "http://api.ceye.io/";
        this.rootDomain = BurpExtender.CeyeDomain;
        this.token = BurpExtender.CeyeToken;
    }

    public boolean supportBatchCheck() {
        return false;
    }

    public String[] batchCheck(String[] payloads) {
        return new String[0];
    }

    public String getName() {
        return "Ceye.io";
    }

    public String getNewPayload() {
        return  this.rootDomain;
    }

    public boolean CheckResult(String domain) {

            for (int i = 0; i < 2; i++) {
                try {
                    Thread.currentThread().sleep(2000);
            Response resp = this.client.newCall(HttpUtils.GetDefaultRequest(this.platformUrl + "v1/records?token=" + this.token + "&type=dns&filter=" + domain.toLowerCase().substring(0, domain.indexOf("."))).build()).execute();
            JSONObject jObj = JSONObject.parseObject(resp.body().string().toLowerCase());
            BurpExtender.stdout.println(jObj.get("data"));
            if (jObj.containsKey("data")) {
                return ((JSONArray)jObj.get("data")).size() > 0;
            }


        } catch (Exception var4) {
            continue;

        }

    }
        return false;
    }


    public boolean flushCache(int count) {
        return this.flushCache();
    }

    public boolean flushCache() {
        return true;
    }

    public boolean getState() {
        return true;
    }

    public void close() {
    }

    public int[] getSupportedPOCTypes() {
        return new int[]{1, 2};
    }
}

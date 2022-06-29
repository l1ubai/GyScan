package burp.ScanFun;

import burp.*;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;

public class SpringBootActuatorScan {
    private static final byte[] Succ_env_v1 = "/env".getBytes();
    private static final byte[] Succ_refresh_v1 = "/heapdump".getBytes();
    private static final byte[] Succ_env_v2 = "actuator/env".getBytes();
    private static final byte[] Succ_refresh_v2 = "actuator/heapdump".getBytes();
    private static final String[] poc_v1 = {"env", "mappings", "gateway","v2/api-docs"};
    private static final String[] poc_v2 = {"actuator/", "actuator/env" };
    private static final byte[] Succ_env = "systemProperties".getBytes();
    private static final String[] poc_jiekou = {};
    private static final byte[] Succ_api = "swagge".getBytes();
    private static final byte[] Succ_druid = "druid".getBytes();
    static PrintWriter stdout;


    public static IHttpRequestResponse ScanMain(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        List headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String reqMethod = helpers.analyzeRequest(baseRequestResponse).getMethod();
        IHttpService httpService = baseRequestResponse.getHttpService();
        byte[] newIHttpRequestResponse = baseRequestResponse.getResponse();
        //获取遍历路径
        List queue = MakeQueue((String) headers.get(0));
        //stdout.println(queue.get(0));
        for (int j = 0; j < queue.size(); j++) {
            String path = (String) queue.get(j);
            //v2检测
            for (int i = 0; i < poc_v2.length; i++) {
                String fpath = AddPoc(path, poc_v2[i]);
                headers.set(0, fpath);
                byte[] body = helpers.buildHttpMessage(headers, null);
                int a = (int) ((Math.random() * 9.0 + 1.0) * 100000.0);
                // headers.add("Testecho:" + a);
                try {
                    Thread.currentThread().sleep(1000);
                    IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                    if (requestResponse != null && requestResponse.getResponse() != null) {
                        byte[] response = requestResponse.getResponse();
                        IResponseInfo responseInfo = helpers.analyzeResponse(response);
                        List<int[]> matches_v2 = getMatches(requestResponse.getResponse(), Succ_env_v2, helpers);
                        if (matches_v2.size() > 0) {
                            List<int[]> matches_v2_2 = getMatches(requestResponse.getResponse(), Succ_refresh_v2, helpers);
                            if (matches_v2_2.size() > 0) {
                                //newissuseL.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                                //issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                                return requestResponse;
                            }
                        }

                    //根据env中systemProperties的来判断是否成功
                    List<int[]> matches_v3 = getMatches(requestResponse.getResponse(), Succ_env, helpers);

                    if (matches_v3.size() > 0) {
                        //BurpExtender.stdout.println("hava env");
                        return requestResponse;

                    }
                    }

                } catch (Exception var21) {
                    stdout.println(var21.getMessage());
                }

            }
            //v1检测
            for (int i = 0; i < poc_v1.length; i++) {
                String fpath = AddPoc(path, poc_v1[i]);
                headers.set(0, fpath);
                byte[] body = helpers.buildHttpMessage(headers, null);
                int a = (int) ((Math.random() * 9.0 + 1.0) * 100000.0);
                // headers.add("Testecho:" + a);
                try {
                    Thread.currentThread().sleep(1000);
                    IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                    if (requestResponse != null && requestResponse.getResponse() != null) {
                        byte[] response = requestResponse.getResponse();
                        IResponseInfo responseInfo = helpers.analyzeResponse(response);
                        List respHeaders = responseInfo.getHeaders();
                        List<int[]> matches_v1 = getMatches(requestResponse.getResponse(), Succ_env_v1, helpers);
                        if (matches_v1.size() > 0) {
                            List<int[]> matches_v1_2 = getMatches(requestResponse.getResponse(), Succ_refresh_v1, helpers);
                            if (matches_v1_2.size() > 0) {
                                return requestResponse;
                            }
                        }
                        //根据env中systemProperties的来判断是否成功
                        List<int[]> matches_v3 = getMatches(requestResponse.getResponse(), Succ_env, helpers);

                        if (matches_v3.size() > 0) {
                           // BurpExtender.stdout.println("hava env");
                            return requestResponse;
                        }
                        //BurpExtender.stdout.println("start api");
                        List<int[]> matches_api = getMatches(requestResponse.getResponse(), Succ_api, helpers);
                        if (matches_api.size() > 0) {
                            //BurpExtender.stdout.println("hava api");
                            //newissuseL.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                            //issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                            return requestResponse;
                        }
                    }
                } catch (Exception var21) {
                }
            }
        }
        return null;
    }


    public static IHttpRequestResponse DocrossScan(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        List headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        //获取遍历路径
        List queue = MakeCrossQueue((String) headers.get(0));
        for (int j = 0; j < queue.size(); j++) {
            String path = (String) queue.get(j);
            //v2检测
            for (int i = 0; i < poc_v2.length; i++) {
                String fpath = AddPoc(path, poc_v2[i]);
                headers.set(0, fpath);
                byte[] body = helpers.buildHttpMessage(headers, null);
                int a = (int) ((Math.random() * 9.0 + 1.0) * 100000.0);
                // headers.add("Testecho:" + a);
                try {
                    Thread.currentThread().sleep(1000);
                    IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                    if (requestResponse != null && requestResponse.getResponse() != null) {
                        byte[] response = requestResponse.getResponse();
                        IResponseInfo responseInfo = helpers.analyzeResponse(response);
                        List<int[]> matches_v2 = getMatches(requestResponse.getResponse(), Succ_env_v2, helpers);
                        if (matches_v2.size() > 0) {
                            List<int[]> matches_v2_2 = getMatches(requestResponse.getResponse(), Succ_refresh_v2, helpers);
                            if (matches_v2_2.size() > 0) {
                                //newissuseL.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                                //issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                                return requestResponse;
                            }
                        }
                        //根据env中systemProperties的来判断是否成功
                        List<int[]> matches_v3 = getMatches(requestResponse.getResponse(), Succ_env, helpers);
                        {
                            if (matches_v3.size() > 0) {

//                            List issues = new ArrayList(1);
//                            issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{baseRequestResponse}, "111", "1", "High"));
                                return requestResponse;
                                //callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized (..;) ", "version :v1  path: " + fpath, "High"));
                            }
                        }


                    }
                } catch (Exception var21) {

                }
            }
            //v1检测
            for (int i = 0; i < poc_v1.length; i++) {
                String fpath = AddPoc(path, poc_v1[i]);
                headers.set(0, fpath);
                byte[] body = helpers.buildHttpMessage(headers, null);
                int a = (int) ((Math.random() * 9.0 + 1.0) * 100000.0);
                // headers.add("Testecho:" + a);
                try {
                    Thread.currentThread().sleep(1000);
                    IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                    if (requestResponse != null && requestResponse.getResponse() != null) {
                        byte[] response = requestResponse.getResponse();
                        IResponseInfo responseInfo = helpers.analyzeResponse(response);
                        List respHeaders = responseInfo.getHeaders();
                        List<int[]> matches_v1 = getMatches(requestResponse.getResponse(), Succ_env_v1, helpers);
                        if (matches_v1.size() > 0) {
                            List<int[]> matches_v1_2 = getMatches(requestResponse.getResponse(), Succ_refresh_v1, helpers);
                            if (matches_v1_2.size() > 0) {

//                            List issues = new ArrayList(1);
//                            issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{baseRequestResponse}, "111", "1", "High"));
                                return requestResponse;
                                //callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized (..;) ", "version :v1 \n path: " + fpath, "High"));
                            }
                        }
                        //根据env中systemProperties的来判断是否成功
                        List<int[]> matches_v3 = getMatches(requestResponse.getResponse(), Succ_env, helpers);
                        {
                            if (matches_v3.size() > 0) {

//                            List issues = new ArrayList(1);
//                            issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{baseRequestResponse}, "111", "1", "High"));
                                return requestResponse;
                                //callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized (..;) ", "version :v1  path: " + fpath, "High"));
                            }
                        }
                        //BurpExtender.stdout.println("start api");

                        List<int[]> matches_api = getMatches(requestResponse.getResponse(), Succ_api, helpers);
                        if (matches_api.size() > 0) {
                            //BurpExtender.stdout.println("hava api");
                            //newissuseL.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                            //issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                            return requestResponse;
                        }
                    }
                } catch (Exception var21) {

                }
            }
        }
        return null;
    }

    public static List<int[]> getMatches(byte[] response, byte[] match, IExtensionHelpers helpers) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    public static List<String> MakeCrossQueue(String header) {
        if (header.contains("GET /..;/ HTTP")) {
            List<String> headers = new ArrayList<String>();
            headers.add(header);
            return headers;
        }
        if (header.contains("GET /?")) {
            String[] headerr = header.split("/");
            header = "GET /..;/ HTTP/" + headerr[2];
            List<String> headers = new ArrayList<String>();
            headers.add(header);
            return headers;
        }
        String[] exts = header.split("/");
        String ext = exts[exts.length - 1];
        if (header.contains("?")) {
            int index = header.indexOf("?");
            header = header.substring(0, index) + " HTTP/" + ext;
            System.out.println(header);
        }
        List queue = new ArrayList();
        String test = "";
        String[] headers = header.split("/");
        int i = 0;
        String forigin = "";
        for (int o = 0; o < headers.length - 1; o++) {
            if (o == headers.length - 2) {
                forigin += headers[o].split(" ")[0] + "/";
            } else {
                forigin += headers[o] + "/";
            }
        }
        for (i = 0; i < headers.length - 2; i++) {
            String fianlheader = "";
            //System.out.println(forigin);
            forigin = forigin + "..;/";
            fianlheader = forigin + " HTTP/" + ext;
            fianlheader = fianlheader.replace("POST ", "GET ");
            fianlheader = fianlheader.replace("OPTIONS ", "GET ");
            fianlheader = fianlheader.replace("PUT ", "GET ");
            fianlheader = fianlheader.replace("DELETE ", "GET ");
            fianlheader = fianlheader.replace("//", "/");
            queue.add(fianlheader);
            //System.out.println(fianlheader);
        }
        return queue;
    }

    public static List<String> MakeQueue(String header) {
        if (header.contains("GET / HTTP")) {
            List<String> headers = new ArrayList<String>();
            headers.add(header);
            return headers;
        }
        if (header.contains("GET /?")) {
            String[] headerr = header.split("/");
            header = "GET / HTTP/" + headerr[2];
            List<String> headers = new ArrayList<String>();
            headers.add(header);
            return headers;
        }

        int iscanshu = 0;
        String[] exts = header.split("/");
        String ext = exts[exts.length - 1];
        if (header.contains("?")) {
            int index = header.indexOf("?");
            header = header.substring(0, index);
            iscanshu = 1;
        }
        List queue = new ArrayList();
        String test = "";
        String[] headers = header.split("/");
        int i = 0;
        String poc = "env";
        int count = headers.length - 3 + iscanshu;
        int begin = headers.length - 2 + iscanshu;
        for (i = begin; i >= begin - count; i--) {
            String fianlheader = "";
            for (int j = 0; j < i; j++) {
                fianlheader = fianlheader + headers[j] + "/";

            }
            fianlheader = fianlheader + " HTTP/" + ext;
            fianlheader = fianlheader.replace("POST ", "GET ");
            fianlheader = fianlheader.replace("OPTIONS ", "GET ");
            fianlheader = fianlheader.replace("PUT ", "GET ");
            fianlheader = fianlheader.replace("DELETE ", "GET ");
            fianlheader = fianlheader.replace("//", "/");
            queue.add(fianlheader);
            //System.out.println(fianlheader);
        }
        return queue;
    }

    public static String AddPoc(String path, String poc) {
        String fpath = "";
        String[] paths = path.split("/");
        for (int i = 0; i < paths.length; i++) {

            if (i == paths.length - 1) {
                fpath += paths[i];
            } else if (i == paths.length - 2) {
                fpath += poc + " HTTP/";
            } else {
                fpath += paths[i] + "/";
            }

        }
        return fpath;

    }
}

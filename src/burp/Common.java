package burp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import java.io.*;
import java.util.*;
import java.net.URLDecoder;
import java.net.URLEncoder;

public class Common {

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

    //获取返回包体
    public static String getResbody(byte[] res,IExtensionHelpers helpers){
        int bodyOffset = helpers.analyzeResponse(res).getBodyOffset();

        String response = new String(res); //byte[] to String
        String body = response.substring(bodyOffset);
        return body; //String to byte[]

    }

    //根据  headers.get(0)来添加 poc  返回不同参数包含poc的数组
    public static List<String> ParamAddPocGet(String params, String poc) throws UnsupportedEncodingException {
        poc = URLEncoder.encode(poc, "utf-8");
        List<String> param = new ArrayList<String>();
        System.out.println(params);
        if (params.contains("?")) {
            String paramsbefore = params.split("\\?")[0] + "?";
            params = params.split("\\?")[1];

            String ext = " HTTP/" + params.split("/")[1];
            params = params.split("/")[0].split(" HTTP")[0];
            System.out.println(params);
            String fstr = "";
            if (params.contains("&")) {
                String[] strs = params.split("&");
                for (int i = 0; i < strs.length; i++) {
                    fstr = "";
                    String[] strs2 = params.split("&");
                    strs2[i] = strs2[i].split("=")[0] + "=" + poc;
                    for (int j = 0; j < strs.length; j++) {
                        if (j == i) {
                            fstr += strs2[j] + "&";
                        } else {
                            fstr += strs[j] + "&";
                        }
                    }
                    //System.out.println(paramsbefore+fstr.substring(0, fstr.length() - 1) + ext);
                    param.add(paramsbefore + fstr.substring(0, fstr.length() - 1) + ext);
                }
            } else {
                //System.out.println(paramsbefore+params.split("=")[0]+"="+poc + ext);
                param.add(paramsbefore + params.split("=")[0] + "=" + poc + ext);
            }
        }
        return param;
    }

    // get请求向参数添加poc后缀，返回不同替换的数组
    public static List<String> ParamAddPocGetNoreplace(String params, String poc) throws UnsupportedEncodingException {
        poc = URLEncoder.encode(poc, "utf-8");
        List<String> param = new ArrayList<String>();
        System.out.println(params);
        if (params.contains("?")) {
            String paramsbefore = params.split("\\?")[0] + "?";
            params = params.split("\\?")[1];

            String ext = " HTTP/" + params.split("/")[1];
            params = params.split("/")[0].split(" HTTP")[0];
            System.out.println(params);
            String fstr = "";
            if (params.contains("&")) {
                String[] strs = params.split("&");
                for (int i = 0; i < strs.length; i++) {
                    fstr = "";
                    String[] strs2 = params.split("&");
                    strs2[i] = strs2[i] + poc;
                    for (int j = 0; j < strs.length; j++) {
                        if (j == i) {
                            fstr += strs2[j] + "&";
                        } else {
                            fstr += strs[j] + "&";
                        }
                    }
                    //System.out.println(paramsbefore+fstr.substring(0, fstr.length() - 1) + ext);
                    param.add(paramsbefore + fstr.substring(0, fstr.length() - 1) + ext);
                }
            } else {
                //System.out.println(paramsbefore+params.split("=")[0]+"="+poc + ext);
                param.add(paramsbefore + params + poc + ext);
            }
        }
        return param;
    }


    // 返回将post参数逐个替换为poc的数组
    public static List<String> ParamAddPocPost(String params, String poc) {
        List<String> param = new ArrayList<String>();
        //System.out.println(params);
        String fstr = "";
        if (params.contains("&")) {
            String[] strs = params.split("&");
            for (int i = 0; i < strs.length; i++) {
                fstr = "";
                String[] strs2 = params.split("&");
                strs2[i] = strs2[i].split("=")[0] + "=" + poc;

                for (int j = 0; j < strs.length; j++) {
                    if (j == i) {
                        fstr += strs2[j] + "&";
                    } else {
                        fstr += strs[j] + "&";
                    }
                }

                //System.out.println(fstr.substring(0, fstr.length() - 1));
                param.add(fstr.substring(0, fstr.length() - 1));

            }
        } else {
           // System.out.println(params.split("=")[0] + "=" + poc);
            param.add(params.split("=")[0] + "=" + poc);
        }

        return param;
    }


    // 返回将post参数逐个添加poc后缀的数组
    public static List<String> ParamAddPocPostNoreplace(String params, String poc) {
        List<String> param = new ArrayList<String>();
        //System.out.println(params);
        String fstr = "";
        if (params.contains("&")) {
            String[] strs = params.split("&");
            for (int i = 0; i < strs.length; i++) {
                fstr = "";
                String[] strs2 = params.split("&");
                strs2[i] = strs2[i]+ poc;

                for (int j = 0; j < strs.length; j++) {
                    if (j == i) {
                        fstr += strs2[j] + "&";
                    } else {
                        fstr += strs[j] + "&";
                    }
                }

                //System.out.println(fstr.substring(0, fstr.length() - 1));
                param.add(fstr.substring(0, fstr.length() - 1));

            }
        } else {
            // System.out.println(params.split("=")[0] + "=" + poc);
            param.add(params+poc);
        }

        return param;
    }

    // 返回将post参数逐个替换为poc的数组（json格式）
    public static List ParamAddPocPostJson(String json,String poc){
        List<String> target = new ArrayList<String>();
        try {
            JSONObject jsonObject = JSONObject.parseObject(json);
            Object origin;
            Map param = new HashMap();
            for (Map.Entry entry : jsonObject.entrySet()) {
                String object = jsonObject.getString(String.valueOf(entry.getKey()));
                origin = jsonObject.get((String) entry.getKey());
                jsonObject.put((String) entry.getKey(), poc);
                //System.out.println(jsonObject.toString());
                target.add(jsonObject.toString());
                jsonObject.put((String) entry.getKey(), origin);
            }
        }
        catch(Exception e){
            BurpExtender.stdout.println(json+"json 类型转换出现了问题");
        }
        return target;
    }

    // 返回将post参数逐个添加poc后缀的数组（json格式）

    public static List ParamAddPocPostJsonNoreplace(String json,String poc){
        List<String> target = new ArrayList<String>();
        try {
            JSONObject jsonObject = JSONObject.parseObject(json);
            Object origin;
            Map param = new HashMap();
            for (Map.Entry entry : jsonObject.entrySet()) {
                String object = jsonObject.getString(String.valueOf(entry.getKey()));
                origin = jsonObject.get((String) entry.getKey());
                //BurpExtender.stdout.println(origin);
                jsonObject.put((String) entry.getKey(), origin+poc);
                //System.out.println(jsonObject.toString());
                target.add(jsonObject.toString());
                jsonObject.put((String) entry.getKey(), origin);
            }
        }
        catch(Exception e){
            BurpExtender.stdout.println(json+"json 类型转换出现了问题");
        }
        return target;
    }

    public static JSONObject readerMethod(File file) throws IOException {
        FileReader fileReader = new FileReader(file);
        Reader reader = new InputStreamReader(new FileInputStream(file), "Utf-8");
        int ch = 0;
        StringBuffer sb = new StringBuffer();
        while ((ch = reader.read()) != -1) {
            sb.append((char) ch);
        }
        fileReader.close();
        reader.close();
        String jsonStr = sb.toString();
        return JSON.parseObject(jsonStr);
    }
    public static byte[] getpostParams(int start, byte[] srcbody) {

        byte[] reqbody = new byte[srcbody.length - start];
        System.arraycopy(srcbody, start, reqbody, 0, srcbody.length - start);

        return reqbody;
    }

    public static boolean SimpleJudgeSpringboot(List<String> headers){
        for (String head:headers
        ) {
            if(head.contains("ASP.NET") || head.contains("PHP/") || head.contains("AspNet") || head.contains("Microsoft-IIS") || head.contains("ThinkPHP")){
                BurpExtender.stdout.println("发现不是springboot，不扫描这个。");
                return false;
            }
        }
        return true;
    }
    public static boolean SimpleJudgeSpringboot(String head){

        head=head.toLowerCase(Locale.ROOT);

        if(head.contains(".phtml") || head.contains(".jsp") || head.contains(".asp") || head.contains(".php") || head.contains(".ashx") || head.contains(".html")){
            BurpExtender.stdout.println("发现不是springboot，不扫描这个。");
            return false;
        }

        return true;
    }
    //通过后缀来判断php
    public static boolean SimpleJudgePhp(String head){

        head=head.toLowerCase(Locale.ROOT);

        if(head.contains(".phtml")  || head.contains(".php")){
            //BurpExtender.stdout.println("");
            return true;
        }

        return false;
    }
    //通过返回头来进行判断php
    public static boolean SimpleJudgePhp2(List<String> headers){

        for (String head:headers
        ) {
            if(head.contains("PHP/") || head.contains("ThinkPHP")){
                //BurpExtender.stdout.println("发现不是springboot，不扫描这个。");
                return true;
            }
        }
        return false;
    }
    //通过后缀来判断java
    public static boolean SimpleJudgeJava(String head){

        head=head.toLowerCase(Locale.ROOT);

        if(head.contains(".phtml")  || head.contains(".php") || head.contains(".asp") || head.contains(".aspx") || head.contains(".ashx")){
            //BurpExtender.stdout.println("");
            return false;
        }

        return true;
    }

    //通过返回头来进行判断java
    public static boolean SimpleJudgeJava2(List<String> headers){

        for (String head:headers
        ) {
            if(head.contains("ASP.NET") || head.contains("PHP/") || head.contains("AspNet") || head.contains("Microsoft-IIS") || head.contains("ThinkPHP")){
                //BurpExtender.stdout.println("发现不是springboot，不扫描这个。");
                return false;
            }
        }
        return true;
    }

    public static boolean IsHaveParams(IHttpRequestResponse base,IExtensionHelpers helpers){
        List<String> headers=helpers.analyzeRequest(base.getRequest()).getHeaders();
        String reqMethod=helpers.analyzeRequest(base.getRequest()).getMethod();

        if(reqMethod.toLowerCase(Locale.ROOT).equals("get"))
        {
            if(headers.get(0).contains("?"))
            {
                return true;
            }
        }

        if(reqMethod.toLowerCase(Locale.ROOT).equals("post"))
        {
            if((getResbody(base.getRequest(),helpers).contains("=")) || getResbody(base.getRequest(),helpers).contains(":"))
            {
                return true;
            }
        }



        return false;
    }

}

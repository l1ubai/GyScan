package burp;

import burp.ScanFun.*;
import com.alibaba.fastjson.JSONObject;
import org.checkerframework.checker.units.qual.C;

import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController {

    public static PrintWriter stdout;
    static PrintWriter stderr;
    static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private String ExtenderName = "All ALl ALl Scan";
    List<IScanIssue> issues = new ArrayList();
    private List Udatas = new ArrayList();
    private List ulists = new ArrayList();
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private URLTable Utable;
    private JScrollPane UscrollPane;
    private JSplitPane HjSplitPane;
    private JPanel mjPane;
    private JTabbedPane Ltable;
    private JTabbedPane Rtable;
    private JSplitPane mjSplitPane;
    //mac
    static File file = new File("/Users/hh/Desktop/plugin/SpringActuator-Unauthorized-Scan-main/src/config.json");
    //win
    //static File file = new File("C://config.json");
    static JSONObject configjson;

    static {
        try {
            configjson = Common.readerMethod(file);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String BlackListstr = (String) configjson.get("blacklist");
    public String[] BlackList = BlackListstr.split(",");

    Boolean Log4j = (Boolean) configjson.get("log4j");
    Boolean Thinkphp = (Boolean) configjson.get("thinkphp");
    Boolean Shiro = (Boolean) configjson.get("shiro");
    Boolean SqlInjection = (Boolean) configjson.get("sqlinjection");
    Boolean SpringCloud = (Boolean) configjson.get("springcloud");
    Boolean Fastjson = (Boolean) configjson.get("fastjson");
    Boolean SpringActuator_Cross = (Boolean) configjson.get("SpringActuator Cross");
    Boolean levelMake = (Boolean) configjson.get("levelMake");
    Boolean Weblogic = (Boolean) configjson.get("weblogic");
    public static String CeyeDomain = configjson.getString("ceyeDomain");
    public static String CeyeToken = configjson.getString("ceyeToken");

    //private String[] BlackList = {"googleapis.com", "mozilla.cloudflare-dns.com", "mozilla.com", "mumu.nie.netease.com", "wx.qlogo.cn", "qq.com", "mozilla.org", "firefoxchina.cn", "baidu.com", "bdstatic.com","firefox.cn","mozilla.net","fofa.info","qpic.cn"};
    private String[] BlackHouzhui = {".css", ".js", ".png", ".jpg", ".gif", ".jpeg", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".iso", ".xlsx", ".docs", ".doc", ".xls", ".ios", ".apk", ".mp3", ".mp4", ".swf"};


    public ArrayList<String> Hostlist = new ArrayList<String>();
    private IScannerCheck scanner;

    public BurpExtender() throws IOException {
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.printOutput(ExtenderName);
        File file = new File("/Users/hh/Desktop/plugin/SpringActuator-Unauthorized-Scan-main/src/config.json");
        //Common.readerMethod(file);
        //stdout.println(ExtenderName);
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        this.stdout.println("===========================");
        this.stdout.println("[+]   load successful!     ");
        this.stdout.println("[+]Scna Scan Scan ALL!!!!!!");
        this.stdout.println("[+]   code by zzzz v1.5     ");
        this.stdout.println("===========================");

        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                BurpExtender.this.mjSplitPane = new JSplitPane(0);
                BurpExtender.this.Utable = BurpExtender.this.new URLTable(BurpExtender.this);
                BurpExtender.this.UscrollPane = new JScrollPane(BurpExtender.this.Utable);
                BurpExtender.this.HjSplitPane = new JSplitPane();
                BurpExtender.this.HjSplitPane.setDividerLocation(0.5);
                BurpExtender.this.Ltable = new JTabbedPane();
                BurpExtender.this.HRequestTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.Ltable.addTab("Request", BurpExtender.this.HRequestTextEditor.getComponent());
                BurpExtender.this.Rtable = new JTabbedPane();
                BurpExtender.this.HResponseTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.Rtable.addTab("Response", BurpExtender.this.HResponseTextEditor.getComponent());
                BurpExtender.this.HjSplitPane.add(BurpExtender.this.Ltable, "left");
                BurpExtender.this.HjSplitPane.add(BurpExtender.this.Rtable, "right");
                BurpExtender.this.mjSplitPane.add(BurpExtender.this.UscrollPane, "left");
                BurpExtender.this.mjSplitPane.add(BurpExtender.this.HjSplitPane, "right");
                BurpExtender.this.callbacks.customizeUiComponent(BurpExtender.this.mjSplitPane);
                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
            }
        });
        callbacks.setExtensionName(ExtenderName);
        callbacks.registerContextMenuFactory(new Menu(this));
        callbacks.registerScannerCheck(this);

    }


    public void doThinkphpScan(IHttpRequestResponse baseRequestResponse) {
        try {
            IHttpRequestResponse thinkreqres = ThinkphpScan.ThinkphpScanall(baseRequestResponse, helpers, callbacks);
            if (thinkreqres != null && thinkreqres.getResponse() != null) {
                if (IsneedAddIssuse(thinkreqres, "thinkphp")) {
                    Addissuse(thinkreqres, "thinkphp rce");
                }
            }
        } catch (Exception e) {
            stdout.println("thinkphp 扫描出错" + e);
        }
    }


    private List<int[]> getMatches(byte[] response, byte[] match) {
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


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        Short LevelCross = 1;
        Short Leveluspath = 1;


        if (Istarget(baseRequestResponse) && Paichu(baseRequestResponse)) {
            List<String> resheaders = helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders();
            String requrl = helpers.analyzeRequest(baseRequestResponse.getRequest()).getHeaders().get(0);
            try {  //判断等级
                if (levelMake) {
                    int index = IsMakeLevel(baseRequestResponse);
                    //stdout.println("index:" + index);
                    if (index == -1) {

                        Map<String, Short> level = JudgeWaf.ReturnLevel(baseRequestResponse, helpers, callbacks);
                        Hostlist.add(baseRequestResponse.getHttpService().getHost() + "/" + String.valueOf(level.get("cross")) + "/" + String.valueOf(level.get("uspath")));
                        stdout.println(baseRequestResponse.getHttpService().getHost() + "等级判断完毕 ： " + String.valueOf(level.get("cross")) + "/" + String.valueOf(level.get("uspath")));
                        //stdout.println("size:" + String.valueOf(Hostlist.size()));
                        LevelCross = level.get("cross");
                        Leveluspath = level.get("uspath");
                    } else {
                        String[] ListLevel = Hostlist.get(index).split("/");
                        LevelCross = Short.valueOf(ListLevel[1]);
                        Leveluspath = Short.valueOf(ListLevel[2]);
                    }

                } else {
                    LevelCross = 1;
                    Leveluspath = 1;
                }
            } catch (Exception e) {
                stderr.println("被动扫描判断等级出现错误");
            }


            try {
                if (IsneedScan(baseRequestResponse, "SpringActuator") && Common.SimpleJudgeSpringboot(resheaders) && Common.SimpleJudgeSpringboot(requrl)) {


                    //Spring boot actuator scan--------------------------------------------------------------
                    List newissuseL = new ArrayList();
                    IHttpRequestResponse actuatorrequestResponse = SpringBootActuatorScan.ScanMain(baseRequestResponse, callbacks, helpers);
                    if (actuatorrequestResponse != null && actuatorrequestResponse.getResponse() != null) {
                        if (helpers.analyzeRequest(actuatorrequestResponse.getRequest()).getHeaders().get(0).contains("v2/api-docs")) {
                            if (IsneedAddIssuse(actuatorrequestResponse, "Swagger-ui api")) {
                                Addissuse(actuatorrequestResponse, "Swagger-ui api");
                                //return newissuseL;
                            }
                        } else {
                            if (IsneedAddIssuse(actuatorrequestResponse, "SpringActuator")) {
                                Addissuse(actuatorrequestResponse, "SpringActuator");
                                //return newissuseL;
                            }
                        }
                    } else {
                        if (LevelCross == 1 && SpringActuator_Cross) {
                            actuatorrequestResponse = SpringBootActuatorScan.DocrossScan(baseRequestResponse, callbacks, helpers);
                            if (actuatorrequestResponse != null && actuatorrequestResponse.getResponse() != null) {
                                if (helpers.analyzeRequest(actuatorrequestResponse.getRequest()).getHeaders().get(0).contains("v2/api-docs")) {
                                    if (IsneedAddIssuse(actuatorrequestResponse, "Swagger-ui api")) {
                                        Addissuse(actuatorrequestResponse, "Swagger-ui api");
                                        //return newissuseL;
                                    }
                                } else {
                                    if (IsneedAddIssuse(actuatorrequestResponse, "SpringActuator")) {
                                        Addissuse(actuatorrequestResponse, "SpringActuator (;)");
                                    }
                                }
                            }
                        }

                    }
                }
            } catch (Exception e) {
                stderr.println("被动扫描spring出现错误" + e);
            }
            //Spring end----------------------------------------

            try {

                if (IsneedScan(baseRequestResponse, "Log4j")) {

                    if (Leveluspath == 1 && Log4j) {
                        if (Common.IsHaveParams(baseRequestResponse, helpers)) {
                            stdout.println("即将对" + baseRequestResponse.getHttpService() + "发起参数处Log4j扫描");
                            IHttpRequestResponse requestResponsep = Log4jScan.ScanParam(baseRequestResponse, callbacks, helpers);

                            if (requestResponsep != null && requestResponsep.getResponse() != null) {
                                if (IsneedAddIssuse(requestResponsep, "Log4j")) {
                                    Addissuse(requestResponsep, "Log4j Rce");
                                }
                            }
                        }
                        stdout.println("即将对" + baseRequestResponse.getHttpService() + "发起请求头处Log4j扫描");
                        IHttpRequestResponse requestResponseh = Log4jScan.ScanHeader(baseRequestResponse, callbacks, helpers);

                        if (requestResponseh != null && requestResponseh.getResponse() != null) {
                            if (IsneedAddIssuse(requestResponseh, "Log4j")) {

                                Addissuse(requestResponseh, "Log4j Rce");

                            }
                        }
                    }
                    //Log4jScan.ScanHeader(baseRequestResponse,callbacks,helpers);
                }
            }
            //Log4j end-----------------------------------------

            catch (Exception e) {
                stderr.println("被动扫描Log4j出现错误" + e);
            }


            try {
                if (IsneedScan(baseRequestResponse, "Shiro")) {
                    if (Shiro) {
                        IHttpRequestResponse shiroreqres = ShiroScan.IsShiro(baseRequestResponse, callbacks, helpers);
                        if (shiroreqres != null && shiroreqres.getResponse() != null) {
                            if (IsneedAddIssuse(shiroreqres, "Shiro")) {
                                Addissuse(shiroreqres, "Shiro");
                            }
                        }
                    }
                }
            } catch (Exception e) {
                stdout.println("shiro 判断出错" + e);
            }

            //shiro end-------------------------------

            if (IsneedScan(baseRequestResponse, "SpringCloud") && Common.SimpleJudgeSpringboot(resheaders) && Common.SimpleJudgeSpringboot(requrl))
                try {
                    if (Leveluspath == 1 && SpringCloud) {
                        IHttpRequestResponse cloudreqres = SpringCloudScan.CloudScan(baseRequestResponse, callbacks, helpers);

                        if (cloudreqres != null && cloudreqres.getResponse() != null) {
                            if (IsneedAddIssuse(cloudreqres, "SpringCloud")) {
                                Addissuse(cloudreqres, "SpringCloud Function Rce");
                            }
                        }
                    }

                } catch (Exception e) {
                    BurpExtender.stdout.println("Spring Cloud扫描出错" + e);
                }


//Spring cloud end-------------------------------
            if (IsneedScan(baseRequestResponse, "Fastjson") && Common.SimpleJudgeSpringboot(resheaders) && Common.SimpleJudgeSpringboot(requrl)) {
                try {
                    if (Leveluspath == 1 && Fastjson) {
                        IHttpRequestResponse fjreqres = FastJsonScan.FastjsonScan(baseRequestResponse, callbacks, helpers);
                        if (fjreqres != null && fjreqres.getResponse() != null) {
                            if (IsneedAddIssuse(fjreqres, "Fastjson")) {
                                Addissuse(fjreqres, "Fastjson Deserialization vulnerability");
                            }
                        }
                    }
                } catch (Exception e) {
                    stdout.println("fastjson 扫描出错" + e);
                }
            }

//fastjson end-------------------------------
            if (IsneedScan(baseRequestResponse, "SqlInjection")) {
                try {
                    if (Leveluspath == 1 && SqlInjection && Common.IsHaveParams(baseRequestResponse, helpers)) {
                        IHttpRequestResponse sqlreqres = SqlInjectionScan.ScanSqlInjectionParam(baseRequestResponse, callbacks, helpers);
                        if (sqlreqres != null && sqlreqres.getResponse() != null) {
                            if (IsneedAddIssuse(sqlreqres, "SqlInjection")) {
                                Addissuse(sqlreqres, "SqlInjection Found!");
                            }
                        }
                    }
                } catch (Exception e) {
                    stdout.println("SqlInjection 扫描出错" + e);
                }
            }


//sqlinjection end-------------------------------
            if (IsneedScan(baseRequestResponse, "thinkphp")) {
                try {
                    if (Leveluspath == 1 && Thinkphp && (Common.SimpleJudgePhp(requrl) || Common.SimpleJudgePhp2(resheaders))) {
                        IHttpRequestResponse thinkreqres = ThinkphpScan.ThinkphpScanall(baseRequestResponse, helpers, callbacks);
                        if (thinkreqres != null && thinkreqres.getResponse() != null) {
                            if (IsneedAddIssuse(thinkreqres, "thinkphp")) {
                                Addissuse(thinkreqres, "thinkphp rce");
                            }
                        }
                    }
                } catch (Exception e) {
                    stdout.println("thinkphp 扫描出错" + e);
                }
            }

//thinkphp end-------------------------------
            if (IsneedScan(baseRequestResponse, "weblogic")) {
                try {
                    if (Leveluspath == 1 && Weblogic && Common.SimpleJudgeJava(requrl) && Common.SimpleJudgeJava2(resheaders)) {
                        IHttpRequestResponse weblogicreqres = WeblogicWeakScan.WeblogicBannerPassScan(baseRequestResponse, callbacks, helpers);
                        if (weblogicreqres != null && weblogicreqres.getResponse() != null) {

                            if (IsneedAddIssuse(weblogicreqres, "weblogic")) {
                                Addissuse(weblogicreqres, "weblogic Found");
                            }

                        }
                    }
                } catch (Exception e) {
                    stdout.println("weblogic 扫描出错" + e);
                }
            }


//weglogic end-------------------------------


//next poc here


        }

        return null;

    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return existingIssue.getHttpService().getHost().equals(newIssue.getHttpService().getHost()) ? 0 : 1;
    }

    public void Addissuse(IHttpRequestResponse reqres, String vulname) {
        URL url = this.helpers.analyzeRequest(reqres).getUrl();
        IHttpService httpService = reqres.getHttpService();
        String reqMethod = this.helpers.analyzeRequest(reqres).getMethod();
        stdout.println(url + vulname + " !存在");
        callbacks.addScanIssue(new CustomScanIssue(reqres.getHttpService(), url, new IHttpRequestResponse[]{reqres}, vulname, "path: " + url, "High"));
        issues.add(new CustomScanIssue(reqres.getHttpService(), url, new IHttpRequestResponse[]{reqres}, vulname, "path: " + url, "High"));
        byte[] newIHttpRequestResponse = reqres.getResponse();
        this.ulists.add(new Ulist(httpService.getHost(), httpService.getPort()));
        synchronized (this.Udatas) {
            int row = this.Udatas.size();
            this.Udatas.add(new TablesData(row, reqMethod, url.toString(), this.helpers.analyzeResponse(newIHttpRequestResponse).getStatusCode() + "", vulname, reqres));
            this.fireTableRowsInserted(row, row);

        }
    }


    //判断url是否需要扫描
    public boolean IsneedScan(IHttpRequestResponse baseRequestResponse, String vul) {

        for (int count = 0; count < issues.size(); count++) {
            if (issues.get(count).getIssueName().contains(vul)) {
                if (issues.get(count).getHttpService().getHost().equals(baseRequestResponse.getHttpService().getHost())) {
                    stdout.println(issues.get(count).getHttpService() + "匹配" + issues.get(count).getIssueName() + "跳过扫描");
                    return false;
                }

            }

        }


        return true;
    }


    //判断是否要加入issuse
    public boolean IsneedAddIssuse(IHttpRequestResponse baseRequestResponse, String vul) {

        for (int count = 0; count < issues.size(); count++) {


            if (issues.get(count).getIssueName().contains(vul)) {
                if (issues.get(count).getHttpService().getHost().equals(baseRequestResponse.getHttpService().getHost())) {
                    stdout.println(issues.get(count).getHttpService() + "匹配" + issues.get(count).getIssueName() + "跳过添加issuse");
                    return false;
                }
            }
        }
        return true;
    }

    //判断是否要扫描
    public boolean Istarget(IHttpRequestResponse baseRequestResponse) {
        for (int i = 0; i < BlackList.length; i++) {
            //包含黑名单
            if (baseRequestResponse.getHttpService().getHost().contains(BlackList[i])) {
                stdout.println(baseRequestResponse.getHttpService().getHost() + "指定不扫描，跳过～");
                return false;
            }
        }
        return true;
    }

    public boolean Paichu(IHttpRequestResponse baseRequestResponse) {
        for (int i = 0; i < BlackHouzhui.length; i++) {
            //已经做过啦

            if (helpers.analyzeRequest(baseRequestResponse).getUrl().toString().toLowerCase().contains(BlackHouzhui[i])) {
                stdout.println(BlackHouzhui[i] + "后缀指定不扫描，跳过～");
                return false;
            }
        }

        return true;
    }

    //判断是否有登记
    public int IsMakeLevel(IHttpRequestResponse baseRequestResponse) {
        for (int i = 0; i < Hostlist.size(); i++) {
            //已经做过啦
            //stdout.println(Hostlist.get(i));
            if (Hostlist.get(i).contains(baseRequestResponse.getHttpService().getHost())) {

                return i;
            }
        }
        stdout.println(baseRequestResponse.getHttpService().getHost() + "还未判断登记，前去判断～");
        return -1;
    }

    public IHttpService getHttpService() {
        return this.currentlyDisplayedItem.getHttpService();
    }

    public byte[] getRequest() {
        return this.currentlyDisplayedItem.getRequest();
    }

    public byte[] getResponse() {
        return this.currentlyDisplayedItem.getResponse();
    }

    public String getTabCaption() {
        return "All All All Scan";
    }

    public Component getUiComponent() {
        return this.mjSplitPane;
    }

    public int getRowCount() {
        return this.Udatas.size();
    }

    public int getColumnCount() {
        return 5;
    }

    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Status";
            case 4:
                return "Issue";
            default:
                return null;
        }
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = (TablesData) this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return datas.Id + 1;
            case 1:
                return datas.Method;
            case 2:
                return datas.URL;
            case 3:
                return datas.Status;
            case 4:
                return datas.issue;
            default:
                return null;
        }
    }

    public static class TablesData {
        final int Id;
        final String Method;
        final String URL;
        final String Status;
        final String issue;
        final IHttpRequestResponse requestResponse;

        public TablesData(int id, String method, String url, String status, String issue, IHttpRequestResponse requestResponse) {
            this.Id = id;
            this.Method = method;
            this.URL = url;
            this.Status = status;
            this.issue = issue;
            this.requestResponse = requestResponse;
        }
    }

    public class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData dataEntry = (TablesData) BurpExtender.this.Udatas.get(this.convertRowIndexToModel(row));
            BurpExtender.this.HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            BurpExtender.this.HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            BurpExtender.this.currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    public class Ulist {
        final String host;
        final int port;

        public Ulist(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }
}



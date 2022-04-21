package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

public class Menu implements IContextMenuFactory {
    BurpExtender burpExtender;

    public Menu(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
    }

    public List createMenuItems(final IContextMenuInvocation invocation) {
        List list = new ArrayList();
        JMenuItem jMenuItem = new JMenuItem("..; Cross Scan");
        list.add(jMenuItem);
        jMenuItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                final IHttpRequestResponse[] requestResponseList = invocation.getSelectedMessages();
                (new Thread(() -> {
                    Menu.this.burpExtender.doScan(requestResponseList[0]);
                })).start();
            }
        });
        return list;
    }
}

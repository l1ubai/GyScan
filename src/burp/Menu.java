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
        JMenuItem jMenuItem = new JMenuItem("Thinkphp Scan");
        JMenuItem jMenuItem2 = new JMenuItem("Thinkphp Scan2");
        list.add(jMenuItem);
        list.add(jMenuItem2);
        jMenuItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                final IHttpRequestResponse[] requestResponseList = invocation.getSelectedMessages();
                (new Thread(() -> {
                    Menu.this.burpExtender.doThinkphpScan(requestResponseList[0]);
                })).start();
            }
        });

        return list;
    }
}

#!/usr/bin/python

import wx

class Example(wx.Frame):
  
    def __init__(self, parent, title):
        super(Example, self).__init__(parent, title=title, 
            size=(490, 350))
            
        self.InitUI()
        self.Centre()
        self.Show()     
        
    def InitUI(self):
        panel = wx.Panel(self)

        font = wx.SystemSettings_GetFont(wx.SYS_SYSTEM_FONT)
        #font.SetPointSize(12)

        vbox = wx.BoxSizer(wx.VERTICAL)

        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        st1 = wx.StaticText(panel, label='Session Name')
        st1.SetFont(font)
        hbox1.Add(st1, flag=wx.RIGHT, border=8)
        tc_name = wx.TextCtrl(panel)
        hbox1.Add(tc_name, proportion=1)
        vbox.Add(hbox1, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)

        vbox.Add((-1, 10))

        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        st2 = wx.StaticText(panel, label='Host')
        st2.SetFont(font)
        hbox2.Add(st2, flag=wx.RIGHT, border=8)
        tc_ip = wx.TextCtrl(panel)
        hbox2.Add(tc_ip, proportion=1)

        st3 = wx.StaticText(panel, label='Port')
        st3.SetFont(font)
        hbox2.Add(st3, flag=wx.LEFT|wx.RIGHT, border=8)
        tc_port = wx.TextCtrl(panel,value="22",size=(font.PixelSize[0]*10,-1))
        hbox2.Add(tc_port, proportion=0)
        vbox.Add(hbox2, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)

        vbox.Add((-1, 10))

        hbox4 = wx.BoxSizer(wx.HORIZONTAL)
        st4 = wx.StaticText(panel, label='Username')
        st4.SetFont(font)
        hbox4.Add(st4, flag=wx.RIGHT, border=8)
        tc_user = wx.TextCtrl(panel)
        hbox4.Add(tc_user, proportion=1)
        vbox.Add(hbox4, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)

        vbox.Add((-1, 10))

        hbox5 = wx.BoxSizer(wx.HORIZONTAL)
        st5 = wx.StaticText(panel, label='Password')
        st5.SetFont(font)
        hbox5.Add(st5, flag=wx.RIGHT, border=8)
        tc_pass = wx.TextCtrl(panel, style=wx.TE_PASSWORD)
        hbox5.Add(tc_pass, proportion=1)
        vbox.Add(hbox5, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)

        vbox.Add((-1, 10))

        panel.SetSizer(vbox)

if __name__ == '__main__':
  
    app = wx.App()
    Example(None, title='MiSSH')
    app.MainLoop()
    

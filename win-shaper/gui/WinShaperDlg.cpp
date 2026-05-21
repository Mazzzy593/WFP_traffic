
// WinShaperDlg.cpp : implementation file
//

#include "stdafx.h"
#include "gui.h"
#include "WinShaperDlg.h"
#include "afxdialogex.h"
#include "CustomProfilesDlg.h"
#include "../driver/interface.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

extern HINSTANCE g_hInstance;

// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
public:
  afx_msg void OnNMClickSyslink1(NMHDR *pNMHDR, LRESULT *pResult);
  afx_msg void OnNMReturnSyslink1(NMHDR *pNMHDR, LRESULT *pResult);
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
  ON_NOTIFY(NM_CLICK, IDC_SYSLINK1, &CAboutDlg::OnNMClickSyslink1)
  ON_NOTIFY(NM_RETURN, IDC_SYSLINK1, &CAboutDlg::OnNMReturnSyslink1)
END_MESSAGE_MAP()


// CWinShaperDlg dialog



CWinShaperDlg::CWinShaperDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_GUI_DIALOG, pParent)
  ,enabled_(false)
  ,driver_interface_(INVALID_HANDLE_VALUE)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CWinShaperDlg::DoDataExchange(CDataExchange* pDX)
{
  CDialogEx::DoDataExchange(pDX);
  DDX_Control(pDX, IDC_CONNECTION_PROFILES, m_profileList);
  DDX_Control(pDX, IDC_ENABLE, m_btnEnable);
  DDX_Control(pDX, IDC_INBOUND_QUEUE, m_inboundQueue);
  DDX_Control(pDX, IDC_OUTBOUND_QUEUE, m_outboundQueue);
}

BEGIN_MESSAGE_MAP(CWinShaperDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
  ON_CBN_SELCHANGE(IDC_CONNECTION_PROFILES, &CWinShaperDlg::OnCbnSelchangeConnectionProfiles)
  ON_BN_CLICKED(IDC_ENABLE, &CWinShaperDlg::OnBnClickedEnable)
  ON_WM_CLOSE()
  ON_WM_TIMER()
END_MESSAGE_MAP()


// CWinShaperDlg message handlers

BOOL CWinShaperDlg::OnInitDialog()
{
  CDialogEx::OnInitDialog();

  // Add "About..." menu item to system menu.

  // IDM_ABOUTBOX must be in the system command range.
  ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
  ASSERT(IDM_ABOUTBOX < 0xF000);

  CMenu* pSysMenu = GetSystemMenu(FALSE);
  if (pSysMenu != NULL)
  {
    BOOL bNameValid;
    CString strAboutMenu;
    bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
    ASSERT(bNameValid);
    if (!strAboutMenu.IsEmpty())
    {
      pSysMenu->AppendMenu(MF_SEPARATOR);
      pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
    }
  }

  // Set the icon for this dialog.  The framework does this automatically
  //  when the application's main window is not a dialog
  SetIcon(m_hIcon, TRUE);			// Set big icon
  SetIcon(m_hIcon, FALSE);		// Set small icon

  PopulateConnectionList();

  return TRUE;  // return TRUE  unless you set the focus to a control
}

void CWinShaperDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
  if ((nID & 0xFFF0) == IDM_ABOUTBOX)
  {
    CAboutDlg dlgAbout;
    dlgAbout.DoModal();
  }
  else
  {
    CDialogEx::OnSysCommand(nID, lParam);
  }
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CWinShaperDlg::OnPaint()
{
  if (IsIconic())
  {
    CPaintDC dc(this); // device context for painting

    SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

    // Center icon in client rectangle
    int cxIcon = GetSystemMetrics(SM_CXICON);
    int cyIcon = GetSystemMetrics(SM_CYICON);
    CRect rect;
    GetClientRect(&rect);
    int x = (rect.Width() - cxIcon + 1) / 2;
    int y = (rect.Height() - cyIcon + 1) / 2;

    // Draw the icon
    dc.DrawIcon(x, y, m_hIcon);
  }
  else
  {
    CDialogEx::OnPaint();
  }
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CWinShaperDlg::OnQueryDragIcon()
{
  return static_cast<HCURSOR>(m_hIcon);
}

void CWinShaperDlg::OnOK()
{
}


void CWinShaperDlg::OnCancel()
{
}

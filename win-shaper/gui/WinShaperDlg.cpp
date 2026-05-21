
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

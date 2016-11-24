
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34058);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2008-0835: openoffice.org");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0835");
 script_set_attribute(attribute: "description", value: '
  Updated openoffice.org packages that fix a security issue are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  OpenOffice.org is an office productivity suite that includes desktop
  applications, such as a word processor, spreadsheet, presentation manager,
  formula editor, and a drawing program.

  A numeric truncation error was found in the OpenOffice.org memory
  allocator. If a carefully crafted file was opened by a victim, an attacker
  could use this flaw to crash OpenOffice.org or, possibly, execute arbitrary
  code. (CVE-2008-3282)

  All users of openoffice.org are advised to upgrade to these updated
  packages, which contain a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0835.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3282");
script_summary(english: "Check for the version of the openoffice.org packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openoffice.org-base-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-calc-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-core-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-draw-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-emailmerge-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-graphicfilter-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-headless-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-impress-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-javafilter-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-af_ZA-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ar-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-as_IN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-bg_BG-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-bn-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ca_ES-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-cs_CZ-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-cy_GB-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-da_DK-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-de-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-el_GR-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-es-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-et_EE-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-eu_ES-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-fi_FI-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-fr-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ga_IE-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-gl_ES-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-gu_IN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-he_IL-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-hi_IN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-hr_HR-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-hu_HU-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-it-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ja_JP-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-kn_IN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ko_KR-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-lt_LT-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ml_IN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-mr_IN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ms_MY-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-nb_NO-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-nl-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-nn_NO-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-nr_ZA-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-nso_ZA-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-or_IN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-pa_IN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-pl_PL-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-pt_BR-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-pt_PT-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ru-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-sk_SK-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-sl_SI-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-sr_CS-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ss_ZA-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-st_ZA-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-sv-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ta_IN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-te_IN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-th_TH-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-tn_ZA-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-tr_TR-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ts_ZA-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ur-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-ve_ZA-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-xh_ZA-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-zh_CN-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-zh_TW-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-langpack-zu_ZA-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-math-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-pyuno-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-testtools-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-writer-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-xsltfilter-2.3.0-6.5.2.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

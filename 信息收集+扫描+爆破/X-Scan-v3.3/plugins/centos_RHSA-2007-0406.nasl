#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if ( description )
{
 script_id(25495);
 script_version("$Revision: 1.5 $");
 script_name(english:"CentOS : RHSA-2007-0406");
 script_set_attribute(attribute: "synopsis", value: "The remote host is missing a security update.");
 script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2007-0406.");
 script_set_attribute(attribute: "see_also", value:
"https://rhn.redhat.com/errata/RHSA-2007-0406.html");
 script_set_attribute(attribute: "solution", value:
"Upgrade to the newest packages by doing :

  yum update");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_end_attributes();

script_cve_id("CVE-2007-0245");

 script_summary(english:"Checks for missing updates on the remote CentOS system");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"CentOS Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/CentOS/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/CentOS/rpm-list") ) exit(1, "Could not obtain the list of packages");

if ( rpm_check(reference:"openoffice.org-1.1.2-39.2.0.EL3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-i18n-1.1.2-39.2.0.EL3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-libs-1.1.2-39.2.0.EL3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-1.1.5-10.6.0.1.EL4", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-base-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-base-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-calc-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-calc-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-core-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-core-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-draw-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-draw-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-emailmerge-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-emailmerge-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-graphicfilter-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-graphicfilter-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-impress-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-impress-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-javafilter-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-javafilter-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-af_ZA-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-af_ZA-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ar-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ar-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-bg_BG-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-bg_BG-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-bn-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-bn-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ca_ES-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ca_ES-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-cs_CZ-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-cs_CZ-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-cy_GB-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-cy_GB-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-da_DK-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-da_DK-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-de-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-de-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-el_GR-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-el_GR-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-es-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-es-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-et_EE-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-et_EE-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-eu_ES-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-eu_ES-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-fi_FI-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-fi_FI-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-fr-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-fr-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ga_IE-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ga_IE-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-gl_ES-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-gl_ES-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-gu_IN-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-gu_IN-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-he_IL-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-he_IL-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-hi_IN-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-hi_IN-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-hr_HR-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-hr_HR-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-hu_HU-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-hu_HU-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-it-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-it-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ja_JP-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ja_JP-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ko_KR-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ko_KR-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-lt_LT-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-lt_LT-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ms_MY-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ms_MY-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-nb_NO-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-nb_NO-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-nl-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-nl-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-nn_NO-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-nn_NO-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-pa_IN-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-pa_IN-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-pl_PL-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-pl_PL-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-pt_BR-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-pt_BR-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-pt_PT-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-pt_PT-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ru-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ru-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-sk_SK-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-sk_SK-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-sl_SI-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-sl_SI-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-sr_CS-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-sr_CS-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-sv-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-sv-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ta_IN-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-ta_IN-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-th_TH-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-th_TH-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-tr_TR-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-tr_TR-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-zh_CN-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-zh_CN-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-zh_TW-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-zh_TW-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-zu_ZA-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-langpack-zu_ZA-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-math-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-math-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-pyuno-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-pyuno-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-testtools-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-testtools-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-writer-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-writer-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-xsltfilter-2.0.4-5.7.0.1.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org2-xsltfilter-2.0.4-5.7.0", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-i18n-1.1.5-10.6.0.1.EL4", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-kde-1.1.5-10.6.0.1.EL4", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-libs-1.1.5-10.6.0.1.EL4", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200905-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(38887);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200905-06");
 script_cve_id("CVE-2009-0798");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200905-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200905-06
(acpid: Denial of Service)


    The acpid daemon allows opening a large number of UNIX sockets without
    closing them, triggering an infinite loop.
  
Impact

    Remote attackers can cause a Denial of Service (CPU consumption and
    connectivity loss).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All acpid users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-power/acpid-1.0.10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0798');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200905-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200905-06] acpid: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'acpid: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-power/acpid", unaffected: make_list("ge 1.0.10"), vulnerable: make_list("lt 1.0.10")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

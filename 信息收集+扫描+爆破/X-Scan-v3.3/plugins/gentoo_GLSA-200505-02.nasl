# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-02.xml
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
 script_id(18228);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200505-02");
 script_cve_id("CVE-2005-1121");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-02
(Oops!: Remote code execution)


    A format string flaw has been detected in the my_xlog() function of the
    Oops! proxy, which is called by the passwd_mysql and passwd_pgsql
    module\'s auth() functions.
  
Impact

    A remote attacker could send a specially crafted HTTP request to the
    Oops! proxy, potentially triggering this vulnerability and leading to
    the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Oops! users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-proxy/oops-1.5.24_pre20050503"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1121');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-02] Oops!: Remote code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Oops!: Remote code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/oops", unaffected: make_list("ge 1.5.24_pre20050503"), vulnerable: make_list("lt 1.5.24_pre20050503")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

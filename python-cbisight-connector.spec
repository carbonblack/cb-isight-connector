%define name python-cbisight-connector
%define version 2.0
%define unmangled_version 2.0
%define release 6
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Carbon Black iSIGHT Bridge
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Carbon Black
Url: http://www.carbonblack.com/
Requires: cb-enterprise >= 5.0

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
pyinstaller isight.spec

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%post
#!/bin/sh

mkdir -p /var/log/cb/integrations/isight/
touch /var/log/cb/integrations/isight/isight.log
mkdir -p /var/run/cb/isight-connector

chown -R cb:cb /var/log/cb/integrations/isight
chown -R cb:cb /var/run/cb/isight-connector
chmod +x /usr/share/cb/integrations/isight/isight


%files -f INSTALLED_FILES
%defattr(-,root,root)

Name: libneat
Version: 1.0.2~td1
Release: 1
Summary: NEAT Project
License: BSD
Group: Applications/Internet
URL: https://github.com/NEAT-project/neat
Source: %{name}-%{version}.tar.gz

AutoReqProv: on
BuildRequires: cmake
BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: jansson-devel
BuildRequires: ldns-devel
BuildRequires: libmnl-devel
BuildRequires: lksctp-tools-devel
BuildRequires: openssl-devel
BuildRequires: libuv-devel
# BuildRequires: libusrsctp-devel
BuildRoot: %{_tmppath}/%{name}-%{version}-build

%description
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.

%prep
%setup -q

%build
%cmake -DCMAKE_INSTALL_PREFIX=/usr -DSOCKET_API=1 -DUSRSCTP_SUPPORT=0 -DSCTP_MULTISTREAMING=1 -DFLOW_GROUPS=1 .
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%files
%{_libdir}/libneat.so*


%package devel
Summary: NEAT (Core API Development Files)
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: libuv-devel

%description devel
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the built examples for the NEAT Core API.

%files devel
%{_includedir}/neat.h
%{_libdir}/libneat-static.a
%{_libdir}/libneat[^\-]*so


%package examples
Summary: NEAT (Core API Examples)
Group: Applications/Internet
Requires: %{name} = %{version}-%{release}

%description examples
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the built examples for the NEAT Core API.

%files examples
%{_libdir}/libneat/client
%{_libdir}/libneat/client_data
%{_libdir}/libneat/client_http_get
%{_libdir}/libneat/client_http_run_once
%{_libdir}/libneat/msbench
%{_libdir}/libneat/peer
%{_libdir}/libneat/server_chargen
%{_libdir}/libneat/server_daytime
%{_libdir}/libneat/server_discard
%{_libdir}/libneat/server_echo
%{_libdir}/libneat/server_http
%{_libdir}/libneat/tneat
%{_libdir}/libneat/minimal_client
%{_libdir}/libneat/minimal_server
%{_libdir}/libneat/minimal_server2
%{_libdir}/libneat/client_dtls_echo
%{_libdir}/libneat/server_dtls_echo


%package socketapi
Summary: NEAT (Socket API Library)
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description socketapi
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the library for the NEAT Sockets API.

%files socketapi
%{_libdir}/libneat-socketapi.so*


%package socketapi-devel
Summary: NEAT (Socket API Development Files)
Group: Development/Libraries
Requires: %{name}-devel = %{version}-%{release}
Requires: %{name}-socketapi = %{version}-%{release}

%description socketapi-devel
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the built examples for the NEAT Sockets API.

%files socketapi-devel
%{_includedir}/neat-socketapi.h
%{_libdir}/libneat-socketapi-static.a
%{_libdir}/libneat-socketapi*.so


%package socketapi-examples
Summary: NEAT (Socket API Examples)
Group: Applications/Internet
Requires: %{name}-socketapi = %{version}-%{release}

%description socketapi-examples
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the built examples for the NEAT Sockets API.

%files socketapi-examples
%{_libdir}/libneat/httpget
%{_libdir}/libneat/httpserver1
%{_libdir}/libneat/httpserver2-select
%{_libdir}/libneat/httpserver2-threads


%changelog
* Thu Dec 05 2019 Thomas Dreibholz <dreibh@iem.uni-due.de> - 1.0.1
- New upstream release.
* Fri Aug 23 2019 Thomas Dreibholz <dreibh@iem.uni-due.de> - 1.0.0
- New upstream release.
* Fri Dec 02 2016 Thomas Dreibholz <dreibh@simula.no> 0.0.1
- Initial RPM release

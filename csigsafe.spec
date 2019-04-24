Name:       csigsafe
Version:    1.00.7.gc2dba00
Release:    1%{?dist}
Summary:    TODO
License:    GPLv3+
URL:        https://github.com/dkozovsk/%{name}
Source0:    %{name}-%{version}.tar.xz

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: gcc-plugin-devel
BuildRequires: cmake

%description
TODO

%global HANDLER_PLUGIN_DIR %(gcc -print-file-name=plugin)

%prep
%setup

%build
export CXXFLAGS="%{optflags}"
make

%install
install -m0755 -d $RPM_BUILD_ROOT%{HANDLER_PLUGIN_DIR}
install -m0755 csigsafe.so $RPM_BUILD_ROOT%{HANDLER_PLUGIN_DIR}

%files
%{HANDLER_PLUGIN_DIR}/*.so

%check
make test


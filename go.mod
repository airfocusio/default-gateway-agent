module github.com/choffmeister/default-gateway-agent

go 1.14

require (
	github.com/godbus/dbus v0.0.0-20151105175453-c7fdd8b5cd55 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/prometheus/client_golang v1.8.0
	github.com/sparrc/go-ping v0.0.0-20190613174326-4e5b6552494c
	github.com/vishvananda/netlink v1.1.1-0.20200625175047-bca67dfc8220
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae // indirect
	golang.org/x/net v0.0.0-20200707034311-ab3426394381 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	k8s.io/apimachinery v0.0.0-20170416202754-ce019b30a1f4
	k8s.io/apiserver v0.0.0-20170417203629-48bf36441a1c
	k8s.io/kubernetes v1.13.0-alpha.0.0.20180917200753-80fb2be3e42e
	k8s.io/utils v0.0.0-20180817171939-982821ea41da
)

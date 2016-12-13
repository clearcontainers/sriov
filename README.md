# sriov
Simple standalone Docker Plugin implementation to demonstrate Clear Containers with SRIOV

For more details about Clear Containers https://github.com/01org/cc-oci-runtime https://clearlinux.org/clear-containers

This plugin supports Docker containers with runc or Clear Containers as the OCI runtime. The plugin is responsible for assigning a SRIOV Virtual Function (VF) into the container namespace.

In the case of runc containers, the VF is directly usable by the container. 

In the case of clear containers, if clear containers detect a VF in the namespace, the runtime will unbind the VF from the host, bind it to VFIO and assign it to the clear container using PCI device pass thro.
The clear container runtime which support SRIOV can be found at https://github.com/01org/cc-oci-runtime/tree/networking/sriov

# sriov
Simple standalone Docker Plugin implementation to demonstrate Clear Containers with SRIOV

For more details about Clear Containers https://github.com/01org/cc-oci-runtime https://clearlinux.org/clear-containers

This plugin supports Docker containers with runc or Clear Containers as the OCI runtime. The plugin is responsible for assigning a SRIOV Virtual Function (VF) into the container namespace.

In the case of runc containers, the VF is directly usable by the container. 

In the case of clear containers, if clear containers detect a VF in the namespace, the runtime will unbind the VF from the host, bind it to VFIO and assign it to the clear container using PCI device pass thro.
The clear container runtime which support SRIOV can be found at https://github.com/01org/cc-oci-runtime/tree/networking/sriov

# How to use this plugin


0. Build this plugin.

        go build

1. Ensure that your plugin is discoverable https://docs.docker.com/engine/extend/plugin_api/#/plugin-discovery

        sudo cp sriov.json /etc/docker/plugins


2. Start the plugin

        sudo ./sriov &

3. Create a mapping file to relate the network interface name of the SRIOV NIC Physical Function (PF) and the name of physical network the NIC is part of. 
   For example, the network interface name corresponding to PF is eth0 and the NIC is part of the physical network b2b
        sudo mkdir /tmp/vfvlan
        sudo touch /tmp/vfvlan/b2b
        sudo vi /tmp/vfvlan/b2b

        eth0

4. Try plugin with Docker runc containers

        #Create a virtual network on physical network b2b with vlanid 100
        sudo docker network create -d sriov --internal --opt phys_network=b2b --opt vlanid=100 vfnet

        #Create container on the network vfnet
        sudo docker run --net=vfnet -itd busybox top

        #Check that your containers are running
        sudo docker ps

        #Cleanup
        sudo docker stop $(sudo docker ps -a -q)
        sudo docker rm $(sudo docker ps -a -q)
        sudo docker network rm vfnet

4. Try plugin with Docker Clear containers
   For Clear Containers, the steps to create network and container are essentially the same. 
   However, before we create Clear Container using SRIOV, host OS needs to boot with intel_iommu=on and have vfio-pci module loaded.

//
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"
        "os"
        "strconv"
        "strings"

	"github.com/boltdb/bolt"
	"github.com/docker/libnetwork/drivers/remote/api"
	ipamapi "github.com/docker/libnetwork/ipams/remote/api"
	"github.com/gorilla/mux"
	"github.com/golang/glog"
        "github.com/vishvananda/netlink"
)

type epVal struct {
        Id        string
        SrcName   string
        Config    vfinfo
}

type vfinfo struct {
        Bdf string
        Id  int
}

type nwVal struct {
       Id       string
       Config configuration
}

type configuration struct {
       Iface           string
       Pf              string
       Vlanid          int
       Phys_network    string
}

type epMap struct {
        sync.Mutex
	m map[string]*epVal
}

type pfMap struct {
        sync.Mutex
        m map[string][]vfinfo
}
type nwMap struct {
        sync.Mutex
	m map[string]*nwVal
}

var driver struct {
    networks nwMap
    endpoints epMap
    pfs pfMap
}

var dbFile string
var db *bolt.DB

const (
      network_to_if_path = "/tmp/vfvlan/"
      sys_class_net_path = "/sys/class/net/"
      pci_devices_path = "/sys/bus/pci/devices/"
)

func init() {
	driver.networks = nwMap{}
        driver.networks.m = make(map[string]*nwVal)

        driver.pfs = pfMap{}
        driver.pfs.m = make(map[string][]vfinfo)

        driver.endpoints = epMap{}
        driver.endpoints.m = make(map[string]*epVal)

	dbFile = "/tmp/bolt.db"
}

//We should never see any errors in this function
func sendResponse(resp interface{}, w http.ResponseWriter) {
	rb, err := json.Marshal(resp)
	if err != nil {
		glog.Errorf("unable to marshal response %v", err)
	}
	glog.Infof("Sending response := %v, %v", resp, err)
	fmt.Fprintf(w, "%s", rb)
	return
}

func getBody(r *http.Request) ([]byte, error) {
	body, err := ioutil.ReadAll(r.Body)
	glog.Infof("URL [%s] Body [%s] Error [%v]", r.URL.Path[1:], string(body), err)
	return body, err
}

func handler(w http.ResponseWriter, r *http.Request) {
	body, _ := getBody(r)
	resp := api.Response{}
	resp.Err = "Unhandled API request " + string(r.URL.Path[1:]) + " " + string(body)
	sendResponse(resp, w)
}

func handlerPluginActivate(w http.ResponseWriter, r *http.Request) {
	_, _ = getBody(r)
	//TODO: Where is this encoding?
	resp := `{
    "Implements": ["NetworkDriver"]
}`
	fmt.Fprintf(w, "%s", resp)
}

func handlerGetCapabilities(w http.ResponseWriter, r *http.Request) {
	_, _ = getBody(r)
	resp := api.GetCapabilityResponse{Scope: "local"}
	sendResponse(resp, w)
}

func handlerCreateNetwork(w http.ResponseWriter, r *http.Request) {
	resp := api.CreateNetworkResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.CreateNetworkRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	v, ok := req.Options["com.docker.network.generic"].(map[string]interface{})
	if !ok {
		resp.Err = "Error: network options incorrect or unspecified. Please provide bridge info"
		sendResponse(resp, w)
		return
	}

	phys_network, ok := v["phys_network"].(string)

        Iface, ok := v["pf_iface"].(string)

        if (phys_network == "") && (Iface == "") {
                resp.Err = "Error: network incorrect or unspecified. Please provide either name of interface connected to physical network (pf_iface) or name of physical network (phys_network)"
                sendResponse(resp, w)
                return
        }

        vlanid, ok := v["vlanid"].(string)
        if !ok {
                resp.Err = "Error: network incorrect or unspecified. Please provide vlan id for the virtual network (vlanid)"
                sendResponse(resp, w)
                return
        }

        nw := &nwVal {
             Id: req.NetworkID,
             Config: configuration{},
        }

        nw.Config.Phys_network = phys_network
        nw.Config.Vlanid, _ = strconv.Atoi(vlanid)
        nw.Config.Iface = Iface

        err = SetupInterface(nw)

        if err != nil {
                resp.Err = err.Error()
                sendResponse(resp, w)
                return
        }


	driver.networks.Lock()
	defer driver.networks.Unlock()

	//Record the docker network UUID to SDN bridge mapping
	//This has to survive a plugin crash/restart and needs to be persisted
	driver.networks.m[req.NetworkID] = nw

	if err := dbAdd("nwMap", req.NetworkID, driver.networks.m[req.NetworkID]); err != nil {
		glog.Errorf("Unable to update db %v", err)
	}

	sendResponse(resp, w)
}

func SetupInterface (nw *nwVal) error {
        if nw.Config.Phys_network != "" {

                map_path := network_to_if_path + nw.Config.Phys_network
                glog.Infof("vfvlan - map path: %s", map_path)

                map_file, err := os.Open(map_path)
                if err != nil {
                        glog.Errorf("vfvlan - Unable to open the opening physical network to iface mapping file %s", nw.Config.Phys_network)
                        return fmt.Errorf("Error with mapping physical network to SR-IOv PF")
                }

                scanner := bufio.NewScanner(map_file)
                scanner.Scan()
                nw.Config.Iface = scanner.Text()
                glog.Infof("vfvlan - interface used for network %s - %s", nw.Id, nw.Config.Iface)
        }

        if_device_path := sys_class_net_path + nw.Config.Iface + "/" + "device"
        glog.Infof("vfvlan - iface device path for network %s - %s", nw.Id, if_device_path)

        device_info, err := os.Readlink(if_device_path)
        if err != nil {
                glog.Errorf("vfvlan - Unable to open the device path for iface %s", nw.Config.Iface)
                return fmt.Errorf("Error with mapping physical network to SR-IOv PF")
        }

        substrings := strings.SplitN(device_info, "/", 4)
        device_bdf := substrings[3]

        nw.Config.Pf = device_bdf
        glog.Infof("vfvlan - iface b.d.f for networks %s - %s", nw.Id, nw.Config.Pf)

        driver.pfs.Lock()

        _, ok := driver.pfs.m[nw.Config.Pf]
        if (ok) {
                glog.Infof("vfvlan - SR-IOv interface for network %s is already initialized", nw.Id)
                driver.pfs.Unlock()
                return nil
        } else {
                driver.pfs.m[nw.Config.Pf] = make([]vfinfo, 0)
        }

        err = initialize_pf(nw.Config.Pf)
        driver.pfs.Unlock()

        if err != nil {
                return fmt.Errorf("Error with initializing the underlying SR-IOv PF")
        }
        return nil
}

func initialize_pf (pf string) error {
        var totalvfs_path, numvfs_path, totalvfs string

        device_path := pci_devices_path + pf

        totalvfs_path = device_path + "/" + "sriov_totalvfs"
        totalvfs_file, err := os.Open(totalvfs_path)

        if err != nil {
                glog.Errorf("Error opening the totalvfs filr on the PF");
                return err
        }

        totalvfs_scanner := bufio.NewScanner(totalvfs_file)
        totalvfs_scanner.Scan()
        totalvfs = totalvfs_scanner.Text()

        numvfs_path = device_path + "/" + "sriov_numvfs"
        numvfs_file, err := os.Open(numvfs_path)

        numvfs_scanner := bufio.NewScanner(numvfs_file)
        numvfs_scanner.Scan()
        numvfs := numvfs_scanner.Text()

        if strings.EqualFold (totalvfs, numvfs) == false {
                glog.Errorf("Numvfs and Totalvfs are not same on the PF - Initialize numvfs to totalvfs")
//                return fmt.Errorf("Error with initializing the underlying SR-IOv PF")
        }

        device_info, err := os.Open(device_path)
        device_info_files, err := device_info.Readdir(0)
        if err == nil {
                for _, value := range device_info_files {
                        if strings.Contains(value.Name(), "virtfn") {
                                link, _ := os.Readlink(device_path + "/" + value.Name())
                                substrings := strings.SplitN(link, "/", 2)
                                device_bdf := substrings[1]
                                vf_id_str := strings.TrimPrefix(value.Name(), "virtfn")
                                vf_id, _ := strconv.Atoi(vf_id_str)
                                vf_info := vfinfo{
                                        Bdf: device_bdf,
                                        Id:  vf_id,
                                }
                                driver.pfs.m[pf] = append(driver.pfs.m[pf], vf_info)
                                glog.Infof("vfvlan" + device_bdf)
                        }
                }
        }
        return nil

}

func handlerDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	resp := api.DeleteNetworkResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DeleteNetworkRequest{}
	if err = json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	glog.Infof("Delete Network := %v", req.NetworkID)

	//This would have already been done in the SDN controller
	//Remove the UUID to bridge mapping in cache and in the
	//persistent data store
	driver.networks.Lock()
	delete(driver.networks.m, req.NetworkID)
	if err := dbDelete("nwMap", req.NetworkID); err != nil {
		glog.Errorf("Unable to update db %v", err)
	}
	driver.networks.Unlock()

	sendResponse(resp, w)
	return
}

func handlerEndpointOperInfof(w http.ResponseWriter, r *http.Request) {
	resp := api.EndpointInfoResponse{}
	body, err := getBody(r)

	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.EndpointInfoRequest{}
	err = json.Unmarshal(body, &req)

	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	resp := api.CreateEndpointResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.CreateEndpointRequest{}
	if err = json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	if req.Interface.Address == "" {
		resp.Err = "Error: IP Address parameter not provided in docker run"
		sendResponse(resp, w)
		return
	}

	ip, _, err := net.ParseCIDR(req.Interface.Address)
	if err != nil {
		resp.Err = "Error: Invalid IP Address " + err.Error()
		sendResponse(resp, w)
		return
	}

        glog.Infof("IP from the docker default IPAM [%v]", ip.String())

        driver.networks.Lock()
        nw := driver.networks.m[req.NetworkID]
        driver.networks.Unlock()

        pf := nw.Config.Pf

	driver.endpoints.Lock()
	defer driver.endpoints.Unlock()

	driver.pfs.Lock()
	defer driver.pfs.Unlock()

        ep := &epVal {
                Id: req.EndpointID,
        }

        glog.Infof("vfvlan - CreateEndpoint number of VFs available %d", len(driver.pfs.m[pf]))

        if len(driver.pfs.m[pf]) == 0 {
                glog.Infof("All the vfs on this interface are currently in use");
                resp.Err = fmt.Sprintf("No VFs are available on the SR-IOv PF")
                sendResponse(resp, w)
                return
        } else {
                ep.Config = driver.pfs.m[pf][0]
                driver.pfs.m[pf] = driver.pfs.m[pf][1:]
        }

	driver.endpoints.m[req.EndpointID] = ep

	if err := dbAdd("epMap", req.EndpointID, driver.endpoints.m[req.EndpointID]); err != nil {
		glog.Errorf("Unable to update db %v", err)
	}

	sendResponse(resp, w)
}

func handlerDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	resp := api.DeleteEndpointResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DeleteEndpointRequest{}
	if err = json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	driver.endpoints.Lock()
        driver.pfs.Lock()
        nw := driver.networks.m[req.NetworkID]
        pf := nw.Config.Pf

        ep := driver.endpoints.m[req.EndpointID]
        driver.pfs.m[pf] = append(driver.pfs.m[pf], ep.Config)

        pf_link, _ := netlink.LinkByName(nw.Config.Iface)
        err = netlink.LinkSetVfVlan(pf_link, ep.Config.Id, 0)

        glog.Infof("vfvlan - DeleteEndpoint number of VFs available %d", len(driver.pfs.m[pf]))
	delete(driver.endpoints.m, req.EndpointID)
	if err := dbDelete("epMap", req.EndpointID); err != nil {
		glog.Errorf("Unable to update db %v", err)
	}
	driver.endpoints.Unlock()
        driver.pfs.Unlock()
	//Figure out how to a vpp tap delete

	sendResponse(resp, w)
}

func handlerJoin(w http.ResponseWriter, r *http.Request) {
	resp := api.JoinResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.JoinRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

        driver.networks.Lock()
        driver.endpoints.Lock()

	nw := driver.networks.m[req.NetworkID]
	em := driver.endpoints.m[req.EndpointID]

	driver.networks.Unlock()
	driver.endpoints.Unlock()

        pf_link, _ := netlink.LinkByName(nw.Config.Iface)
        err = netlink.LinkSetVfVlan(pf_link, em.Config.Id, nw.Config.Vlanid)

        vf_path := pci_devices_path + em.Config.Bdf
        vf_iface := vf_path + "/net"
        iface_info, _ := os.Open(vf_iface)
        iface_info_dir, err := iface_info.Readdir(0)
        if err == nil {
                for _, value := range iface_info_dir {
                        em.SrcName = value.Name()
                        glog.Infof("vfvlan - ep srcname %s", em.SrcName)
                }
        }

        resp.InterfaceName = &api.InterfaceName{
		SrcName:   em.SrcName,
		DstPrefix: "eth",
	}
	glog.Infof("Join Response %v", resp)
	sendResponse(resp, w)
}

func handlerLeave(w http.ResponseWriter, r *http.Request) {
	resp := api.LeaveResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.LeaveRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerDiscoverNew(w http.ResponseWriter, r *http.Request) {
	resp := api.DiscoveryResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DiscoveryNotification{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerDiscoverDelete(w http.ResponseWriter, r *http.Request) {
	resp := api.DiscoveryResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DiscoveryNotification{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerExternalConnectivity(w http.ResponseWriter, r *http.Request) {
	resp := api.ProgramExternalConnectivityResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.ProgramExternalConnectivityRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerRevokeExternalConnectivity(w http.ResponseWriter, r *http.Request) {
	resp := api.RevokeExternalConnectivityResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.RevokeExternalConnectivityResponse{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func ipamGetCapabilities(w http.ResponseWriter, r *http.Request) {
	if _, err := getBody(r); err != nil {
		glog.Infof("ipamGetCapabilities: unable to get request body [%v]", err)
	}
	resp := ipamapi.GetCapabilityResponse{RequiresMACAddress: true}
	sendResponse(resp, w)
}

func ipamGetDefaultAddressSpaces(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.GetAddressSpacesResponse{}
	if _, err := getBody(r); err != nil {
		glog.Infof("ipamGetDefaultAddressSpaces: unable to get request body [%v]", err)
	}

	resp.GlobalDefaultAddressSpace = ""
	resp.LocalDefaultAddressSpace = ""
	sendResponse(resp, w)
}

func ipamRequestPool(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.RequestPoolResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.RequestPoolRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	resp.PoolID = uuid.Generate().String()
	resp.Pool = req.Pool
	sendResponse(resp, w)
}

func ipamReleasePool(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.ReleasePoolResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.ReleasePoolRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func ipamRequestAddress(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.RequestAddressResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.RequestAddressRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	//TODO: Should come from the subnet mask for the subnet
	if req.Address != "" {
		resp.Address = req.Address + "/24"
	} else {
		resp.Error = "Error: Request does not have IP address. Specify using --ip"
	}
	sendResponse(resp, w)
}

func ipamReleaseAddress(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.ReleaseAddressResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.ReleaseAddressRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func dbTableInit(tables []string) (err error) {

	glog.Infof("dbInit Tables := %v", tables)
	for i, v := range tables {
		glog.Infof("table[%v] := %v, %v", i, v, []byte(v))
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, table := range tables {
			_, err := tx.CreateBucketIfNotExists([]byte(table))
			if err != nil {
				return fmt.Errorf("Bucket creation error: %v %v", table, err)
			}
		}
		return nil
	})

	if err != nil {
		glog.Errorf("Table creation error %v", err)
	}

	return err
}

func dbAdd(table string, key string, value interface{}) (err error) {

	err = db.Update(func(tx *bolt.Tx) error {
		var v bytes.Buffer

		if err := gob.NewEncoder(&v).Encode(value); err != nil {
			glog.Errorf("Encode Error: %v %v", err, value)
			return err
		}

		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("Bucket %v not found", table)
		}

		err = bucket.Put([]byte(key), v.Bytes())
		if err != nil {
			return fmt.Errorf("Key Store error: %v %v %v %v", table, key, value, err)
		}
		return nil
	})

	return err
}

func dbDelete(table string, key string) (err error) {

	err = db.Update(func(tx *bolt.Tx) error {

		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("Bucket %v not found", table)
		}

		err = bucket.Delete([]byte(key))
		if err != nil {
			return fmt.Errorf("Key Delete error: %v %v ", key, err)
		}
		return nil
	})

	return err
}

func dbGet(table string, key string) (value interface{}, err error) {

	err = db.View(func(tx *bolt.Tx) error {

		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("Bucket %v not found", table)
		}

		val := bucket.Get([]byte(key))
		if val == nil {
			return nil
		}

		v := bytes.NewReader(val)
		if err := gob.NewDecoder(v).Decode(value); err != nil {
			glog.Errorf("Decode Error: %v %v %v", table, key, err)
			return err
		}

		return nil
	})

	return value, err
}

func initDb() error {

	options := bolt.Options{
		Timeout: 3 * time.Second,
	}

	var err error
	db, err = bolt.Open(dbFile, 0644, &options)
	if err != nil {
		return fmt.Errorf("dbInit failed %v", err)
	}

	tables := []string{"global", "nwMap", "epMap"}
	if err := dbTableInit(tables); err != nil {
		return fmt.Errorf("dbInit failed %v", err)
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nwMap"))

		err := b.ForEach(func(k, v []byte) error {
			vr := bytes.NewReader(v)
			nVal := &nwVal{}
			if err := gob.NewDecoder(vr).Decode(nVal); err != nil {
				return fmt.Errorf("Decode Error: %v %v %v", string(k), string(v), err)
			}
			driver.networks.m[string(k)] = nVal
			glog.Infof("nwMap key=%v, value=%v\n", string(k), nVal)
			return nil
		})
		return err
	})

	if err != nil {
		return err
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("epMap"))

		err := b.ForEach(func(k, v []byte) error {
			vr := bytes.NewReader(v)
			eVal := &epVal{}
			if err := gob.NewDecoder(vr).Decode(eVal); err != nil {
				return fmt.Errorf("Decode Error: %v %v %v", string(k), string(v), err)
			}
			driver.endpoints.m[string(k)] = eVal
			glog.Infof("epMap key=%v, value=%v\n", string(k), eVal)
			return nil
		})
		return err
	})

	return err
}

func main() {
	flag.Parse()

	if err := initDb(); err != nil {
		glog.Fatalf("db init failed, quitting [%v]", err)
	}
	defer func() {
		err := db.Close()
		glog.Errorf("unable to close database [%v]", err)
	}()

	r := mux.NewRouter()
	r.HandleFunc("/Plugin.Activate", handlerPluginActivate)
	r.HandleFunc("/NetworkDriver.GetCapabilities", handlerGetCapabilities)
	r.HandleFunc("/NetworkDriver.CreateNetwork", handlerCreateNetwork)
	r.HandleFunc("/NetworkDriver.DeleteNetwork", handlerDeleteNetwork)
	r.HandleFunc("/NetworkDriver.CreateEndpoint", handlerCreateEndpoint)
	r.HandleFunc("/NetworkDriver.DeleteEndpoint", handlerDeleteEndpoint)
	r.HandleFunc("/NetworkDriver.EndpointOperInfo", handlerEndpointOperInfof)
	r.HandleFunc("/NetworkDriver.Join", handlerJoin)
	r.HandleFunc("/NetworkDriver.Leave", handlerLeave)
	r.HandleFunc("/NetworkDriver.DiscoverNew", handlerDiscoverNew)
	r.HandleFunc("/NetworkDriver.DiscoverDelete", handlerDiscoverDelete)
	r.HandleFunc("/NetworkDriver.ProgramExternalConnectivity", handlerExternalConnectivity)
	r.HandleFunc("/NetworkDriver.RevokeExternalConnectivity", handlerRevokeExternalConnectivity)


	r.HandleFunc("/", handler)
	err := http.ListenAndServe("127.0.0.1:9599", r)
	if err != nil {
		glog.Errorf("docker plugin http server failed, [%v]", err)
	}
}

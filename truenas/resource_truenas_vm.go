package truenas

import (
	"context"
	api "github.com/dariusbakunas/truenas-go-sdk"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"strconv"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sort"
)

func deviceKey(d api.VMDevice) string {
	keys := make([]string, 0, len(d.Attributes))
	for k := range d.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := []string{d.Dtype}
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, d.Attributes[k]))
	}

	return strings.Join(parts, "|")
}


func resourceTrueNASVM() *schema.Resource {
	return &schema.Resource{
		ReadContext:   resourceTrueNASVMRead,
		CreateContext: resourceTrueNASVMCreate,
		DeleteContext: resourceTrueNASVMDelete,
		UpdateContext: resourceTrueNASVMUpdate,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"vm_id": &schema.Schema{
				Description: "VM ID",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"name": &schema.Schema{
				Description: "VM name",
				Type:        schema.TypeString,
				Required:    true,
			},
			"description": &schema.Schema{
				Description: "VM description",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"bootloader": &schema.Schema{
				Description:  "VM bootloader",
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"UEFI", "UEFI_CSM", "GRUB"}, false),
				Default:      "UEFI",
			},
			"autostart": &schema.Schema{
				Description: "Set to start this VM when the system boots",
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
			},
			"time": &schema.Schema{
				Description:  "VM system time. Default is `Local`",
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOCAL",
				ValidateFunc: validation.StringInSlice([]string{"LOCAL", "UTC"}, false),
			},
			"shutdown_timeout": &schema.Schema{
				Description: "The time in seconds the system waits for the VM to cleanly shut down. During system shutdown, the system initiates poweroff for the VM after the shutdown timeout has expired.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "90",
			},
			"vcpus": &schema.Schema{
				Description: "Number of virtual CPUs to allocate to the virtual machine. The maximum is 16, or fewer if the host CPU limits the maximum. The VM operating system might also have operational or licensing restrictions on the number of CPUs.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "1",
			},
			"cores": &schema.Schema{
				Description: "Specify the number of cores per virtual CPU socket. The product of vCPUs, cores, and threads must not exceed 16.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "1",
			},
			"threads": &schema.Schema{
				Description: "Specify the number of threads per core. The product of vCPUs, cores, and threads must not exceed 16.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "1",
			},
			"memory": &schema.Schema{
				Description: "Allocate RAM for the VM. Minimum value is 256 * 1024 * 1024 B. Units are bytes. Allocating too much memory can slow the system or prevent VMs from running",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "536870912", // 512MiB
			},
			"device": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": &schema.Schema{
							Description: "Device ID",
							Type:        schema.TypeString,
							Computed:    true,
						},
						"type": &schema.Schema{
							Description:  "Device type",
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringInSlice([]string{"NIC", "DISK", "CDROM", "PCI", "DISPLAY", "RAW"}, false),
						},
						"order": &schema.Schema{
							Description: "Device order",
							Type:        schema.TypeInt,
							Computed:    true,
						},
						"vm": &schema.Schema{
							Description: "Device VM ID",
							Type:        schema.TypeInt,
							Computed:    true,
						},
						"attributes": &schema.Schema{
							Description: "Device attributes specific to device type, check VM resource examples for example device configurations",
							Type:        schema.TypeMap,
							Required:    true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"status": &schema.Schema{
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"state": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
						"pid": &schema.Schema{
							Type:     schema.TypeInt,
							Computed: true,
						},
						"domain_state": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			// ✅ Add dynamic computed fields here
        		"mac": &schema.Schema{
            			Description: "MAC address assigned to the VM NIC",
            			Type:        schema.TypeString,
            			Computed:    true,
        		},
        		"port": &schema.Schema{
            			Description: "Port assigned to the display device",
            			Type:        schema.TypeInt,
            			Computed:    true,
        		},
        		"web_port": &schema.Schema{
            			Description: "Web port assigned to the display device",
            			Type:        schema.TypeInt,
            			Computed:    true,
        		},
		},
	}
}

func resourceTrueNASVMRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	pc := m.(*TrueNASProviderClient)
	c := pc.Client

	id, err := strconv.Atoi(d.Id())

	if err != nil {
		return diag.FromErr(err)
	}

	resp, _, err := c.VmApi.GetVM(ctx, int32(id)).Execute()

	if err != nil {
		return diag.Errorf("error getting VM: %s", err)
	}

	d.Set("name", resp.Name)

	if resp.Bootloader != nil {
		d.Set("bootloader", *resp.Bootloader)
	}

	if resp.Description != nil {
		d.Set("description", *resp.Description)
	}

	if resp.Vcpus != nil {
		d.Set("vcpus", *resp.Vcpus)
	}

	if resp.Cores != nil {
		d.Set("cores", *resp.Cores)
	}

	if resp.Threads != nil {
		d.Set("threads", *resp.Threads)
	}

	if resp.Memory != nil {
		d.Set("memory", *resp.Memory)
	}

	if resp.Autostart != nil {
		d.Set("autostart", *resp.Autostart)
	}

	if resp.ShutdownTimeout != nil {
		d.Set("shutdown_timeout", *resp.ShutdownTimeout)
	}

	if resp.Time != nil {
		d.Set("time", *resp.Time)
	}

	if resp.Devices != nil {
		if err := d.Set("device", flattenVMDevicesForResource(resp.Devices)); err != nil {
			return diag.Errorf("error setting VM devices: %s", err)
		}
	}

	if resp.Status != nil {
		if err := d.Set("status", flattenVMStatus(*resp.Status)); err != nil {
			return diag.Errorf("error setting VM status: %s", err)
		}
	}

	d.Set("vm_id", strconv.Itoa(int(resp.Id)))

	// Extract dynamic values from devices
	for _, dev := range resp.Devices {
		if dev.Dtype == "NIC" {
			if mac, ok := dev.Attributes["mac"].(string); ok {
				d.Set("mac", mac)
			}
		}
		if dev.Dtype == "DISPLAY" {
			if port, ok := dev.Attributes["port"].(float64); ok {
				d.Set("port", int(port))
			}
			if webPort, ok := dev.Attributes["web_port"].(float64); ok {
				d.Set("web_port", int(webPort))
			}
		}
	}

	return nil
}

func resourceTrueNASVMCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	pc := m.(*TrueNASProviderClient)
	c := pc.Client

	input := api.CreateVMParams{
		Name: getStringPtr(d.Get("name").(string)),
	}

	if description, ok := d.GetOk("description"); ok {
		input.Description = getStringPtr(description.(string))
	}

	if bootloader, ok := d.GetOk("bootloader"); ok {
		input.Bootloader = getStringPtr(bootloader.(string))
	}

	if autostart, ok := d.GetOk("autostart"); ok {
		input.Autostart = getBoolPtr(autostart.(bool))
	}

	if time, ok := d.GetOk("time"); ok {
		input.Time = getStringPtr(time.(string))
	}

	if shutdownTimeout, ok := d.GetOk("shutdown_timeout"); ok {
		input.ShutdownTimeout = getInt32Ptr(int32(shutdownTimeout.(int)))
	}

	if vcpus, ok := d.GetOk("vcpus"); ok {
		input.Vcpus = getInt32Ptr(int32(vcpus.(int)))
	}

	if cores, ok := d.GetOk("cores"); ok {
		input.Cores = getInt32Ptr(int32(cores.(int)))
	}

	if threads, ok := d.GetOk("threads"); ok {
		input.Threads = getInt32Ptr(int32(threads.(int)))
	}

	if memory, ok := d.GetOk("memory"); ok {
		input.Memory = getInt64Ptr(int64(memory.(int)))
	}

	if devices, ok := d.GetOk("device"); ok {
		dv, err := expandVMDevice(devices.(*schema.Set).List())

		if err != nil {
			return diag.Errorf("error creating VM: %s", err)
		}

		input.Devices = dv
	}

	resp, _, err := c.VmApi.CreateVM(ctx).CreateVMParams(input).Execute()

	if err != nil {
		var body []byte
		if apiErr, ok := err.(*api.GenericOpenAPIError); ok {
			body = apiErr.Body()
		}
		return diag.Errorf("error creating VM: %s\n%s", err, body)
	}

	d.SetId(strconv.Itoa(int(resp.Id)))
	return resourceTrueNASVMRead(ctx, d, m)
}

func resourceTrueNASVMDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	pc := m.(*TrueNASProviderClient)
	c := pc.Client

	id, err := strconv.Atoi(d.Id())

	if err != nil {
		return diag.FromErr(err)
	}

	_, err = c.VmApi.DeleteVM(ctx, int32(id)).Execute()

	if err != nil {
		var body []byte
		if apiErr, ok := err.(*api.GenericOpenAPIError); ok {
			body = apiErr.Body()
		}

		return diag.Errorf("error deleting VM: %s\n%s", err, body)
	}

	d.SetId("")

	return nil
}

func resourceTrueNASVMUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	pc := m.(*TrueNASProviderClient)
	c := pc.Client

	id, err := strconv.Atoi(d.Id())

	if err != nil {
		return diag.FromErr(err)
	}

	input := api.UpdateVMParams{
		Name: getStringPtr(d.Get("name").(string)),
	}

	if d.HasChange("description") {
		input.Description = getStringPtr(d.Get("description").(string))
	}

	if d.HasChange("bootloader") {
		input.Bootloader = getStringPtr(d.Get("bootloader").(string))
	}

	if d.HasChange("autostart") {
		input.Autostart = getBoolPtr(d.Get("autostart").(bool))
	}

	if d.HasChange("time") {
		input.Time = getStringPtr(d.Get("time").(string))
	}

	if d.HasChange("shutdown_timeout") {
		input.ShutdownTimeout = getInt32Ptr(int32(d.Get("shutdown_timeout").(int)))
	}

	if d.HasChange("vcpus") {
		input.Vcpus = getInt32Ptr(int32(d.Get("vcpus").(int)))
	}

	if d.HasChange("cores") {
		input.Cores = getInt32Ptr(int32(d.Get("cores").(int)))
	}

	if d.HasChange("threads") {
		input.Threads = getInt32Ptr(int32(d.Get("threads").(int)))
	}

	if d.HasChange("memory") {
		input.Memory = getInt64Ptr(int64(d.Get("memory").(int)))
	}

	//if d.HasChange("device") {
	//	input.Devices, err = expandVMDeviceForUpdate(d.Get("device").(*schema.Set).List(), getInt32Ptr(int32(id)))

	//	if err != nil {
	//		return diag.Errorf("error updating VM: %s", err)
	//	}
	//}

	_, _, err = c.VmApi.UpdateVM(ctx, int32(id)).UpdateVMParams(input).Execute()

	if d.HasChange("device") {
		deviceList := d.Get("device").(*schema.Set).List()
		devices, err := expandVMDevice(deviceList)
		if err != nil {
			return diag.Errorf("error expanding device list: %s", err)
		}

		err = reconcileDevices(ctx, pc.Client, pc.APIKey, int32(id), devices)
		if err != nil {
			return diag.Errorf("error reconciling devices: %s", err)
		}
	}


	// TODO: handle error response like:
	//{{
	//	"vm_update.name": [
	//{
	//"message": "Only alphanumeric characters are allowed.",
	//"errno": 22
	//}
	//]
	//}}

	if err != nil {
		var body []byte
		if apiErr, ok := err.(*api.GenericOpenAPIError); ok {
			body = apiErr.Body()
		}

		return diag.Errorf("error updating VM: %s\n%s", err, body)
	}

	return resourceTrueNASVMRead(ctx, d, m)
}

// TrueNAS api requires vm attribute set on updates even if it is new device
// while that attribute cannot be set during creation (bug?)
func expandVMDeviceForUpdate(d []interface{}, vmID *int32) ([]api.VMDevice, error) {
	if len(d) == 0 {
		return []api.VMDevice{}, nil
	}

	result := make([]api.VMDevice, 0, len(d))

	for _, item := range d {
		dMap := item.(map[string]interface{})
		dType := dMap["type"].(string)

		if dType == "" {
			continue
		}

		device := &api.VMDevice{
			Dtype: dType,
		}

		// assuming order cannot be 0
		if order, ok := dMap["order"].(int); ok && order != 0 {
			device.Order = getInt32Ptr(int32(order))
		}

		// assuming vm cannot be 0
		device.Vm = vmID

		if idStr, ok := dMap["id"]; ok && idStr != "" {
			id, err := strconv.Atoi(idStr.(string))

			if err != nil {
				return nil, err
			}

			device.Id = getInt32Ptr(int32(id))
		}

		if attr, ok := dMap["attributes"]; ok {
			attrMap := attr.(map[string]interface{})

			// a hack to preserve booleans
			for key, val := range attrMap {
				if val.(string) == "false" {
					attrMap[key] = false
				}
				if val.(string) == "true" {
					attrMap[key] = true
				}
			}

			device.Attributes = attrMap
		}

		result = append(result, *device)
	}

	return result, nil
}

func expandVMDevice(d []interface{}) ([]api.VMDevice, error) {
	if len(d) == 0 {
		return []api.VMDevice{}, nil
	}

	result := make([]api.VMDevice, 0, len(d))

	for _, item := range d {
		dMap := item.(map[string]interface{})
		dType := dMap["type"].(string)

		if dType == "" {
			continue
		}

		device := &api.VMDevice{
			Dtype: dType,
		}

		if attr, ok := dMap["attributes"]; ok {
			attrMap := attr.(map[string]interface{})

			// a hack to preserve booleans
			for key, val := range attrMap {
				if val.(string) == "false" {
					attrMap[key] = false
				}
				if val.(string) == "true" {
					attrMap[key] = true
				}
			}

			device.Attributes = attrMap
		}

		result = append(result, *device)
	}

	return result, nil
}

func reconcileDevices(ctx context.Context, c *api.APIClient, apiKey string, vmID int32, desired []api.VMDevice) error {

	currentResp, _, err := c.VmApi.GetVM(ctx, vmID).Execute()
	if err != nil {
		return fmt.Errorf("error reading VM devices: %w", err)
	}
	current := currentResp.Devices

	currentMap := map[string]api.VMDevice{}
	for _, d := range current {
		key := deviceKey(d)
		currentMap[key] = d
	}

	desiredMap := map[string]api.VMDevice{}
	for _, d := range desired {
		key := deviceKey(d)
		desiredMap[key] = d
	}

	// DELETE removed
	for key, device := range currentMap {
		if _, ok := desiredMap[key]; !ok {
			if device.Id == nil || *device.Id == 0 {
				continue // skip deletion if device ID is missing or invalid
			}

			path := fmt.Sprintf("/vm/device/%d", *device.Id)
			_, err := makeRequest(ctx, c.GetConfig(), apiKey, "DELETE", path, nil)

			// Handle 404s as non-fatal
			if err != nil && strings.Contains(err.Error(), "404") {
				continue
			}

			if err != nil {
				return fmt.Errorf("failed to delete device (ID: %d): %w", *device.Id, err)
			}
		}

	}

	// CREATE new
	for key, device := range desiredMap {
		if _, ok := currentMap[key]; !ok {
			device.Vm = &vmID
			_, err := makeRequest(ctx, c.GetConfig(), apiKey, "POST", "/vm/device/", device)

			if err != nil {
				if strings.Contains(err.Error(), "already configured") {
					continue // device exists, skip
				}
				return fmt.Errorf("failed to create device: %w", err)
			}
		}
	}


	return nil
}

func makeRequest(ctx context.Context, cfg *api.Configuration, apiKey string, method, path string, body interface{}) ([]byte, error) {
	client := &http.Client{}

	baseURL, err := cfg.ServerURLWithContext(ctx, "VMDevice")
	if err != nil {
		return nil, err
	}
	reqURL := fmt.Sprintf("%s%s", baseURL, path)

	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, respBody)
	}

	return respBody, nil
}

func flattenVMDevicesForResource(devices []api.VMDevice) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(devices))

	// Only include user-declared attributes per device type
	allowedAttrs := map[string][]string{
		"NIC":     {"type", "nic_attach", "trust_guest_rx_filters"},
		"DISPLAY": {"type", "resolution", "web", "wait", "password", "bind"},
		"DISK":    {"type", "path"},
		// You can add more for other types like RAW, CDROM, etc.
	}

	for _, d := range devices {
		device := map[string]interface{}{
			"type": d.Dtype,
		}

		flattenedAttrs := make(map[string]string)

		for k, v := range d.Attributes {
			if v == nil {
				continue
			}

			switch val := v.(type) {
			case bool:
				flattenedAttrs[k] = strconv.FormatBool(val)
			case float64:
				// For numbers like port, web_port, etc.
				flattenedAttrs[k] = strconv.Itoa(int(val))
			default:
				flattenedAttrs[k] = fmt.Sprintf("%v", val)
			}
		}

		// Filter to only include expected attributes for that type
		filtered := make(map[string]string)
		if keys, ok := allowedAttrs[d.Dtype]; ok {
			for _, key := range keys {
				if val, exists := flattenedAttrs[key]; exists {
					filtered[key] = val
				}
			}
		} else {
			// Fallback: keep all if type unknown
			filtered = flattenedAttrs
		}

		device["attributes"] = filtered

		// Do NOT include: id, vm, order — let Terraform and TrueNAS manage that silently

		result = append(result, device)
	}

	return result
}


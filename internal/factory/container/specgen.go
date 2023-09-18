package container

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/containers/common/pkg/subscriptions"
	"github.com/containers/common/pkg/util"
	"github.com/containers/podman/v4/pkg/rootless"
	selinux "github.com/containers/podman/v4/pkg/selinux"
	cstorage "github.com/containers/storage"
	"github.com/containers/storage/pkg/idtools"
	"github.com/containers/storage/pkg/mount"
	"github.com/cri-o/cri-o/internal/config/cgmgr"
	"github.com/cri-o/cri-o/internal/config/device"
	"github.com/cri-o/cri-o/internal/config/node"
	"github.com/cri-o/cri-o/internal/config/rdt"
	"github.com/cri-o/cri-o/internal/config/seccomp"
	sconfig "github.com/cri-o/cri-o/pkg/config"

	// ctr "github.com/cri-o/cri-o/internal/factory/container"
	// "github.com/cri-o/cri-o/server"
	"github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/linklogs"
	"github.com/cri-o/cri-o/internal/log"
	oci "github.com/cri-o/cri-o/internal/oci"
	"github.com/cri-o/cri-o/internal/storage"
	crioann "github.com/cri-o/cri-o/pkg/annotations"
	securejoin "github.com/cyphar/filepath-securejoin"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
	"golang.org/x/net/context"
	"golang.org/x/sys/unix"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
	kubeletTypes "k8s.io/kubelet/pkg/types"

	"github.com/intel/goresctrl/pkg/blockio"
)


func (ctr *container) configToSpec(ctx context.Context, serverConfig *sconfig.Config, sb *sandbox.Sandbox) ( seccompRef string, err error){
	containerID := ctr.ID()
	containerConfig := ctr.Config()
	if containerConfig.Linux == nil {
		containerConfig.Linux = &types.LinuxContainerConfig{}
	}
	if containerConfig.Linux.SecurityContext == nil {
		containerConfig.Linux.SecurityContext = newLinuxContainerSecurityContext()
	}
	securityContext := containerConfig.Linux.SecurityContext

	// creates a spec Generator with the default spec.
	specgen := ctr.Spec()
	specgen.HostSpecific = true
	specgen.ClearProcessRlimits()

	for _, u := range serverConfig.Ulimits() {
		specgen.AddProcessRlimits(u.Name, u.Hard, u.Soft)
	}

	readOnlyRootfs := ctr.ReadOnly(serverConfig.ReadOnly)
	specgen.SetRootReadonly(readOnlyRootfs)

	// set this container's apparmor profile if it is set by sandbox
	if serverConfig.AppArmor().IsEnabled() && !ctr.Privileged() {
		profile, err := serverConfig.AppArmor().Apply(
			securityContext.ApparmorProfile,
		)
		if err != nil {
			return nil, fmt.Errorf("applying apparmor profile to container %s: %w", containerID, err)
		}

		log.Debugf(ctx, "Applied AppArmor profile %s to container %s", profile, containerID)
		specgen.SetProcessApparmorProfile(profile)
	}

	metadata := containerConfig.Metadata
	// Get blockio class
	if serverConfig.BlockIO().Enabled() {
		if blockioClass, err := blockio.ContainerClassFromAnnotations(metadata.Name, containerConfig.Annotations, sb.Annotations()); blockioClass != "" && err == nil {
			if linuxBlockIO, err := blockio.OciLinuxBlockIO(blockioClass); err == nil {
				if specgen.Config.Linux.Resources == nil {
					specgen.Config.Linux.Resources = &rspec.LinuxResources{}
				}
				specgen.Config.Linux.Resources.BlockIO = linuxBlockIO
			}
		}
	}

	specgen.SetProcessTerminal(containerConfig.Tty)
	if containerConfig.Tty {
		specgen.AddProcessEnv("TERM", "xterm")
	}

	linux := containerConfig.Linux
	if linux != nil {
		resources := linux.Resources
		if resources != nil {
			specgen.SetLinuxResourcesCPUPeriod(uint64(resources.CpuPeriod))
			specgen.SetLinuxResourcesCPUQuota(resources.CpuQuota)
			specgen.SetLinuxResourcesCPUShares(uint64(resources.CpuShares))

			memoryLimit := resources.MemoryLimitInBytes
			if memoryLimit != 0 {
				if err := cgmgr.VerifyMemoryIsEnough(memoryLimit); err != nil {
					return nil, err
				}
				specgen.SetLinuxResourcesMemoryLimit(memoryLimit)
				if resources.MemorySwapLimitInBytes != 0 {
					if resources.MemorySwapLimitInBytes > 0 && resources.MemorySwapLimitInBytes < resources.MemoryLimitInBytes {
						return nil, fmt.Errorf(
							"container %s create failed because memory swap limit (%d) cannot be lower than memory limit (%d)",
							ctr.ID(),
							resources.MemorySwapLimitInBytes,
							resources.MemoryLimitInBytes,
						)
					}
					memoryLimit = resources.MemorySwapLimitInBytes
				}
				// If node doesn't have memory swap, then skip setting
				// otherwise the container creation fails.
				if node.CgroupHasMemorySwap() {
					specgen.SetLinuxResourcesMemorySwap(memoryLimit)
				}
			}

			specgen.SetProcessOOMScoreAdj(int(resources.OomScoreAdj))
			specgen.SetLinuxResourcesCPUCpus(resources.CpusetCpus)
			specgen.SetLinuxResourcesCPUMems(resources.CpusetMems)

			// If the kernel has no support for hugetlb, silently ignore the limits
			if node.CgroupHasHugetlb() {
				hugepageLimits := resources.HugepageLimits
				for _, limit := range hugepageLimits {
					specgen.AddLinuxResourcesHugepageLimit(limit.PageSize, limit.Limit)
				}
			}

			if node.CgroupIsV2() && len(resources.Unified) != 0 {
				if specgen.Config.Linux.Resources.Unified == nil {
					specgen.Config.Linux.Resources.Unified = make(map[string]string, len(resources.Unified))
				}
				for key, value := range resources.Unified {
					specgen.Config.Linux.Resources.Unified[key] = value
				}
			}
		}

		specgen.SetLinuxCgroupsPath(serverConfig.CgroupManager().ContainerCgroupPath(sb.CgroupParent(), containerID))

		if ctr.Privileged() {
			specgen.SetupPrivileged(true)
		} else {
			capabilities := securityContext.Capabilities
			if err := ctr.SpecSetupCapabilities(capabilities, serverConfig.DefaultCapabilities, serverConfig.AddInheritableCapabilities); err != nil {
				return nil, err
			}
		}
		specgen.SetProcessNoNewPrivileges(securityContext.NoNewPrivs)

		if !ctr.Privileged() {
			if securityContext.MaskedPaths != nil {
				for _, path := range securityContext.MaskedPaths {
					specgen.AddLinuxMaskedPaths(path)
				}
			}

			if securityContext.ReadonlyPaths != nil {
				for _, path := range securityContext.ReadonlyPaths {
					specgen.AddLinuxReadonlyPaths(path)
				}
			}
		}
	}

	if !ctr.Privileged() && node.CgroupIsV2() {
		if err := specgen.AddOrReplaceLinuxNamespace(string(rspec.CgroupNamespace), ""); err != nil {
			return nil, err
		}
	}

	if ctr.Privileged() {
		setOCIBindMountsPrivileged(specgen)
	}

	specgen.SetHostname(sb.Hostname())
	specgen.AddProcessEnv("HOSTNAME", sb.Hostname())

	// created := time.Now()
	seccompRef = types.SecurityProfile_Unconfined.String()
	if !ctr.Privileged() {
		notifier, ref, err := serverConfig.Seccomp().Setup(
			ctx,
			s.seccompNotifierChan,
			containerID,
			sb.Annotations(),
			specgen,
			securityContext.Seccomp,
		)
		if err != nil {
			return "", fmt.Errorf("setup seccomp: %w", err)
		}
		if notifier != nil {
			s.seccompNotifiers.Store(containerID, notifier)
		}
		seccompRef = ref
	}
	// Get RDT class
	rdtClass, err := serverConfig.Rdt().ContainerClassFromAnnotations(metadata.Name, containerConfig.Annotations, sb.Annotations())
	if err != nil {
		return "", err
	}
	if rdtClass != "" {
		log.Debugf(ctx, "Setting RDT ClosID of container %s to %q", containerID, rdt.ResctrlPrefix+rdtClass)
		// TODO: patch runtime-tools to support setting ClosID via a helper func similar to SetLinuxIntelRdtL3CacheSchema()
		specgen.Config.Linux.IntelRdt = &rspec.LinuxIntelRdt{ClosID: rdt.ResctrlPrefix + rdtClass}
	}

	// First add any configured environment variables from crio config.
	// They will get overridden if specified in the image or container config.
	specgen.AddMultipleProcessEnv(s.Config().DefaultEnv)

	// Add environment variables from image the CRI configuration
	envs := mergeEnvs(containerImageConfig, containerConfig.Envs)
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		specgen.AddProcessEnv(parts[0], parts[1])
	}

	// TODO - move setupContainer() to internal/factory
	// Setup user and groups
	if linux != nil {
		if err := setupContainerUser(ctx, specgen, mountPoint, mountLabel, containerInfo.RunDir, securityContext, containerImageConfig); err != nil {
			return "", err
		}
	}

	// TODO - move addImageVolumes() to internal/factory
	// Add image volumes
	volumeMounts, err := addImageVolumes(ctx, mountPoint, s, &containerInfo, mountLabel, specgen)
	if err != nil {
		return nil, err
	}

	// Set working directory
	// Pick it up from image config first and override if specified in CRI
	containerCwd := "/"
	imageCwd := containerImageConfig.Config.WorkingDir
	if imageCwd != "" {
		containerCwd = imageCwd
	}
	runtimeCwd := containerConfig.WorkingDir
	if runtimeCwd != "" {
		containerCwd = runtimeCwd
	}
	specgen.SetProcessCwd(containerCwd)
	if err := setupWorkingDirectory(mountPoint, mountLabel, containerCwd); err != nil {
		return nil, err
	}

	var processLabel string
	if ctr.WillRunSystemd() {
		processLabel, err = selinux.InitLabel(processLabel)
		if err != nil {
			return nil, err
		}
		setupSystemd(specgen.Mounts(), *specgen)
	}

	// TODO - return crioAnnotations

}

func setupWorkingDirectory(rootfs, mountLabel, containerCwd string) error {
	fp, err := securejoin.SecureJoin(rootfs, containerCwd)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(fp, 0o755); err != nil {
		return err
	}
	if mountLabel != "" {
		if err1 := securityLabel(fp, mountLabel, false, false); err1 != nil {
			return err1
		}
	}
	return nil
}

func setOCIBindMountsPrivileged(g *generate.Generator) {
	spec := g.Config
	// clear readonly for /sys and cgroup
	for i := range spec.Mounts {
		clearReadOnly(&spec.Mounts[i])
	}
	spec.Linux.ReadonlyPaths = nil
	spec.Linux.MaskedPaths = nil
}

func clearReadOnly(m *rspec.Mount) {
	var opt []string
	for _, o := range m.Options {
		if o == "rw" {
			return
		} else if o != "ro" {
			opt = append(opt, o)
		}
	}
	m.Options = opt
	m.Options = append(m.Options, "rw")
}

func newLinuxContainerSecurityContext() *types.LinuxContainerSecurityContext {
	return &types.LinuxContainerSecurityContext{
		Capabilities:     &types.Capability{},
		NamespaceOptions: &types.NamespaceOption{},
		SelinuxOptions:   &types.SELinuxOption{},
		RunAsUser:        &types.Int64Value{},
		RunAsGroup:       &types.Int64Value{},
		Seccomp:          &types.SecurityProfile{},
		Apparmor:         &types.SecurityProfile{},
	}
}

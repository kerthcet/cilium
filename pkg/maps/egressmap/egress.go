// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package egressmap

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-egress")

const (
	PolicyMapName = "cilium_egress_policy_v4"

	MaxPolicyEntries = 1 << 14
)

var (
	EgressPolicyMap *egressPolicyMap
)

// ApplyEgressPolicy adds a new entry to the egress policy map.
// If a policy with the same key already exists, it will get replaced.
func ApplyEgressPolicy(sourceIP net.IP, destCIDR net.IPNet, egressIP, gatewayIP net.IP) error {
	logger := log.WithFields(logrus.Fields{
		logfields.SourceIP:        sourceIP,
		logfields.DestinationCIDR: destCIDR,
		logfields.EgressIP:        egressIP,
		logfields.GatewayIP:       gatewayIP,
	})

	if err := EgressPolicyMap.Update(sourceIP, destCIDR, egressIP, gatewayIP); err != nil {
		return fmt.Errorf("cannot apply egress policy: %w", err)
	}

	logger.Info("Applied egress policy")
	return nil
}

// RemoveEgressPolicy removes an egress policy identified by the (source IP,
// destination CIDR) tuple.
func RemoveEgressPolicy(sourceIP net.IP, destCIDR net.IPNet) error {
	if err := EgressPolicyMap.Delete(sourceIP, destCIDR); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("egress policy does not exist")
		}

		return err
	}

	log.WithFields(logrus.Fields{
		logfields.SourceIP:        sourceIP,
		logfields.DestinationCIDR: destCIDR,
	}).Info("Removed egress policy")

	return nil
}

// InitEgressMaps initializes the egress policy map.
func InitEgressMaps() error {
	return initEgressPolicyMap(PolicyMapName, true)
}

// OpenEgressMaps initializes the egress policy map.
func OpenEgressMaps() error {
	return initEgressPolicyMap(PolicyMapName, false)
}

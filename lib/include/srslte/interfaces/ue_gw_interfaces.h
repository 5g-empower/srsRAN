/**
 * Copyright 2013-2021 Software Radio Systems Limited
 *
 * This file is part of srsLTE.
 *
 * srsLTE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsLTE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#ifndef SRSLTE_UE_GW_INTERFACES_H
#define SRSLTE_UE_GW_INTERFACES_H

#include "srslte/asn1/liblte_mme.h"

namespace srsue {

class gw_interface_nas
{
public:
  virtual int setup_if_addr(uint32_t eps_bearer_id,
                            uint32_t lcid,
                            uint8_t  pdn_type,
                            uint32_t ip_addr,
                            uint8_t* ipv6_if_id,
                            char*    err_str)                                                    = 0;
  virtual int apply_traffic_flow_template(const uint8_t&                                 eps_bearer_id,
                                          const uint8_t&                                 lcid,
                                          const LIBLTE_MME_TRAFFIC_FLOW_TEMPLATE_STRUCT* tft) = 0;

  typedef enum {
    TEST_LOOP_INACTIVE = 0,
    TEST_LOOP_MODE_A_ACTIVE,
    TEST_LOOP_MODE_B_ACTIVE,
    TEST_LOOP_MODE_C_ACTIVE
  } test_loop_mode_state_t;

  /**
   * Updates the test loop mode. The IP delay parameter is only valid for Mode B.
   * @param mode
   * @param ip_pdu_delay_ms The PDU delay in ms
   */
  virtual void set_test_loop_mode(const test_loop_mode_state_t mode, const uint32_t ip_pdu_delay_ms = 0) = 0;
};

class gw_interface_rrc
{
public:
  virtual void add_mch_port(uint32_t lcid, uint32_t port)             = 0;
  virtual int  update_lcid(uint32_t eps_bearer_id, uint32_t new_lcid) = 0;
};

class gw_interface_pdcp
{
public:
  virtual void write_pdu(uint32_t lcid, srslte::unique_byte_buffer_t pdu)     = 0;
  virtual void write_pdu_mch(uint32_t lcid, srslte::unique_byte_buffer_t pdu) = 0;
};

class gw_interface_stack : public gw_interface_nas, public gw_interface_rrc, public gw_interface_pdcp
{};

} // namespace srsue

#endif // SRSLTE_UE_GW_INTERFACES_H

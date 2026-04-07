<?php
/**
 * Constants of WPMUDEV class.
 *
 * @package WP_Defender\Behavior
 */

namespace WP_Defender\Behavior;

interface WPMUDEV_Const_Interface {
	public const API_HUB_SYNC                 = 'hub_sync';
	public const API_PACKAGE_CONFIGS          = 'package_configs';
	public const API_GLOBAL_IP_LIST           = 'global_ip_list';
	public const API_IP_BLOCKLIST_SUBMIT_LOGS = 'ip_blocklist_submit_logs';
	public const API_ANTIBOT_GLOBAL_FIREWALL  = 'antibot_global_firewall';
}

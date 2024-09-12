/* packet-cigi.c
 * Routines for Common Image Generator Interface
 * (Versions 2, 3 and 4) dissection
 * CIGI 1-3 - http://cigi.sourceforge.net/
 * Copyright (c) 2005 The Boeing Company
 *
 * CIGI 4 https://www.sisostandards.org/page/StandardsProducts
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Contributors:
 * Kyle J. Harms <kyle.j.harms@boeing.com>
 * Brian M. Ames <bmames@apk.net>
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/tfs.h>

/* Forward declaration */
void proto_register_cigi(void);
void proto_reg_handoff_cigi(void);

static bool packet_is_cigi(tvbuff_t*);
static void dissect_cigi_pdu(tvbuff_t*, packet_info*, proto_tree*);
static void cigi_add_tree(tvbuff_t*, proto_tree*);
static int cigi_add_data(tvbuff_t*, proto_tree*, int);

static void cigi2_add_tree(tvbuff_t*, packet_info*, proto_tree*);
static int cigi2_add_ig_control(tvbuff_t*, proto_tree*, int);
static int cigi2_add_entity_control(tvbuff_t*, proto_tree*, int);
static int cigi2_add_component_control(tvbuff_t*, proto_tree*, int);
static int cigi2_add_articulated_parts_control(tvbuff_t*, proto_tree*, int);
static int cigi2_add_rate_control(tvbuff_t*, proto_tree*, int);
static int cigi2_add_environment_control(tvbuff_t*, proto_tree*, int);
static int cigi2_add_weather_control(tvbuff_t*, proto_tree*, int);
static int cigi2_add_view_control(tvbuff_t*, proto_tree*, int);
static int cigi2_add_sensor_control(tvbuff_t*, proto_tree*, int);
static int cigi2_add_trajectory_definition(tvbuff_t*, proto_tree*, int);
static int cigi2_add_special_effect_definition(tvbuff_t*, proto_tree*, int);
static int cigi2_add_view_definition(tvbuff_t*, proto_tree*, int);
static int cigi2_add_collision_detection_segment_definition(tvbuff_t*, proto_tree*, int);
static int cigi2_add_collision_detection_volume_definition(tvbuff_t*, proto_tree*, int);
static int cigi2_add_height_above_terrain_request(tvbuff_t*, proto_tree*, int);
static int cigi2_add_line_of_sight_occult_request(tvbuff_t*, proto_tree*, int);
static int cigi2_add_line_of_sight_range_request(tvbuff_t*, proto_tree*, int);
static int cigi2_add_height_of_terrain_request(tvbuff_t*, proto_tree*, int);
static int cigi2_add_start_of_frame(tvbuff_t*, proto_tree*, int);
static int cigi2_add_height_above_terrain_response(tvbuff_t*, proto_tree*, int);
static int cigi2_add_line_of_sight_response(tvbuff_t*, proto_tree*, int);
static int cigi2_add_collision_detection_segment_response(tvbuff_t*, proto_tree*, int);
static int cigi2_add_sensor_response(tvbuff_t*, proto_tree*, int);
static int cigi2_add_height_of_terrain_response(tvbuff_t*, proto_tree*, int);
static int cigi2_add_collision_detection_volume_response(tvbuff_t*, proto_tree*, int);
static int cigi2_add_image_generator_message(tvbuff_t*, proto_tree*, int);

static void cigi3_add_tree(tvbuff_t*, packet_info*, proto_tree*);
static int cigi3_add_ig_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_entity_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_conformal_clamped_entity_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_component_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_short_component_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_articulated_part_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_short_articulated_part_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_rate_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_celestial_sphere_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_atmosphere_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_environmental_region_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_weather_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_maritime_surface_conditions_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_wave_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_terrestrial_surface_conditions_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_view_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_sensor_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_motion_tracker_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_earth_reference_model_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_trajectory_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_view_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_collision_detection_segment_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_collision_detection_volume_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_hat_hot_request(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_line_of_sight_segment_request(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_line_of_sight_vector_request(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_position_request(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_environmental_conditions_request(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_start_of_frame(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_hat_hot_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_hat_hot_extended_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_line_of_sight_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_line_of_sight_extended_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_sensor_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_sensor_extended_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_position_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_weather_conditions_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_aerosol_concentration_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_maritime_surface_conditions_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_terrestrial_surface_conditions_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_collision_detection_segment_notification(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_collision_detection_volume_notification(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_animation_stop_notification(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_event_notification(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_add_image_generator_message(tvbuff_t*, packet_info*, proto_tree*, void*);

static int cigi3_3_add_symbol_surface_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_3_add_symbol_text_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_3_add_symbol_circle_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_3_add_symbol_line_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_3_add_symbol_clone(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_3_add_symbol_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi3_3_add_short_symbol_control(tvbuff_t*, packet_info*, proto_tree*, void*);


static void cigi4_add_tree(tvbuff_t*, packet_info*, proto_tree*);
static int cigi4_add_ig_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_entity_position(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_conformal_clamped_entity_position(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_component_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_short_component_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_articulated_part_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_short_articulated_part_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_velocity_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_celestial_sphere_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_atmosphere_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_environmental_region_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_weather_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_maritime_surface_conditions_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_wave_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_terrestrial_surface_conditions_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_view_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_sensor_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_motion_tracker_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_earth_reference_model_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_acceleration_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_view_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_collision_detection_segment_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_collision_detection_volume_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_hat_hot_request(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_line_of_sight_segment_request(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_line_of_sight_vector_request(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_position_request(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_environmental_conditions_request(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_symbol_surface_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_symbol_text_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_symbol_circle_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_symbol_polygon_definition(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_symbol_clone(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_symbol_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_short_symbol_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_symbol_circle_textured(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_entity_control(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_animation_control(tvbuff_t*, packet_info*, proto_tree*, void*);

static int cigi4_add_start_of_frame(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_hat_hot_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_hat_hot_extended_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_line_of_sight_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_line_of_sight_extended_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_sensor_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_sensor_extended_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_position_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_weather_conditions_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_aerosol_concentration_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_maritime_surface_conditions_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_terrestrial_surface_conditions_response(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_collision_detection_segment_notification(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_collision_detection_volume_notification(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_animation_stop_notification(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_event_notification(tvbuff_t*, packet_info*, proto_tree*, void*);
static int cigi4_add_image_generator_message(tvbuff_t*, packet_info*, proto_tree*, void*);

/* CIGI Handle */
static dissector_handle_t cigi_handle;

static dissector_table_t cigi3_packet_id_table;
static dissector_table_t cigi4_packet_id_table;

/* Initialize the protocol and registered fields */
static int proto_cigi;

/* All CIGI Versions */
static int hf_cigi_src_port;
static int hf_cigi_dest_port;
static int hf_cigi_port;
static int hf_cigi_data;
static int hf_cigi_packet_id;
static int hf_cigi_packet_size;
static int hf_cigi_version;

static int hf_cigi_frame_size;

static int hf_cigi_unknown;


static const true_false_string attach_detach_tfs = {
    "Attach",
    "Detach"
};

static const true_false_string entity_geodetic_tfs = {
    "Entity",
    "Geodetic"
};

static const true_false_string extended_normal_tfs = {
    "Extended",
    "Normal"
};

static const true_false_string visible_occluded_tfs = {
    "Visible",
    "Occluded"
};

static const true_false_string visible_occulted_tfs = {
    "Visible",
    "Occulted"
};

/*** Fields for CIGI2 ***/

/* CIGI2 Packet ID */
static int hf_cigi2_packet_id;
#define CIGI2_PACKET_ID_IG_CONTROL                               1
#define CIGI2_PACKET_ID_ENTITY_CONTROL                           2
#define CIGI2_PACKET_ID_COMPONENT_CONTROL                        3
#define CIGI2_PACKET_ID_ARTICULATED_PARTS_CONTROL                4
#define CIGI2_PACKET_ID_RATE_CONTROL                             5
#define CIGI2_PACKET_ID_ENVIRONMENT_CONTROL                      6
#define CIGI2_PACKET_ID_WEATHER_CONTROL                          7
#define CIGI2_PACKET_ID_VIEW_CONTROL                             8
#define CIGI2_PACKET_ID_SENSOR_CONTROL                           9
#define CIGI2_PACKET_ID_TRAJECTORY_DEFINITION                   21
#define CIGI2_PACKET_ID_SPECIAL_EFFECT_DEFINITION               22
#define CIGI2_PACKET_ID_VIEW_DEFINITION                         23
#define CIGI2_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION  24
#define CIGI2_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION   25
#define CIGI2_PACKET_ID_HEIGHT_ABOVE_TERRAIN_REQUEST            41
#define CIGI2_PACKET_ID_LINE_OF_SIGHT_OCCULT_REQUEST            42
#define CIGI2_PACKET_ID_LINE_OF_SIGHT_RANGE_REQUEST             43
#define CIGI2_PACKET_ID_HEIGHT_OF_TERRAIN_REQUEST               44
#define CIGI2_PACKET_ID_START_OF_FRAME                         101
#define CIGI2_PACKET_ID_HEIGHT_ABOVE_TERRAIN_RESPONSE          102
#define CIGI2_PACKET_ID_LINE_OF_SIGHT_RESPONSE                 103
#define CIGI2_PACKET_ID_COLLISION_DETECTION_SEGMENT_RESPONSE   104
#define CIGI2_PACKET_ID_SENSOR_RESPONSE                        105
#define CIGI2_PACKET_ID_HEIGHT_OF_TERRAIN_RESPONSE             106
#define CIGI2_PACKET_ID_COLLISION_DETECTION_VOLUME_RESPONSE    107
#define CIGI2_PACKET_ID_IMAGE_GENERATOR_MESSAGE                108
#define CIGI2_PACKET_ID_USER_DEFINABLE_MIN                     236
#define CIGI2_PACKET_ID_USER_DEFINABLE_MAX                     255
static const value_string cigi2_packet_id_vals[] = {
    {CIGI2_PACKET_ID_IG_CONTROL, "IG Control"},
    {CIGI2_PACKET_ID_ENTITY_CONTROL, "Entity Control"},
    {CIGI2_PACKET_ID_COMPONENT_CONTROL, "Component Control"},
    {CIGI2_PACKET_ID_ARTICULATED_PARTS_CONTROL, "Articulated Parts Control"},
    {CIGI2_PACKET_ID_RATE_CONTROL, "Rate Control"},
    {CIGI2_PACKET_ID_ENVIRONMENT_CONTROL, "Environment Control"},
    {CIGI2_PACKET_ID_WEATHER_CONTROL, "Weather Control"},
    {CIGI2_PACKET_ID_VIEW_CONTROL, "View Control"},
    {CIGI2_PACKET_ID_SENSOR_CONTROL, "Sensor Control"},
    {CIGI2_PACKET_ID_TRAJECTORY_DEFINITION, "Trajectory Definition"},
    {CIGI2_PACKET_ID_SPECIAL_EFFECT_DEFINITION, "Special Effect Definition"},
    {CIGI2_PACKET_ID_VIEW_DEFINITION, "View Definition"},
    {CIGI2_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION, "Collision Detection Segment Definition"},
    {CIGI2_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION, "Collision Detection Volume Definition"},
    {CIGI2_PACKET_ID_HEIGHT_ABOVE_TERRAIN_REQUEST, "Height Above Terrain Request"},
    {CIGI2_PACKET_ID_LINE_OF_SIGHT_OCCULT_REQUEST, "Line of Sight Occult Request"},
    {CIGI2_PACKET_ID_LINE_OF_SIGHT_RANGE_REQUEST, "Line of Sight Range Request"},
    {CIGI2_PACKET_ID_HEIGHT_OF_TERRAIN_REQUEST, "Height of Terrain Request"},
    {CIGI2_PACKET_ID_START_OF_FRAME, "Start of Frame"},
    {CIGI2_PACKET_ID_HEIGHT_ABOVE_TERRAIN_RESPONSE, "Height Above Terrain Response"},
    {CIGI2_PACKET_ID_LINE_OF_SIGHT_RESPONSE, "Line of Sight Response"},
    {CIGI2_PACKET_ID_COLLISION_DETECTION_SEGMENT_RESPONSE, "Collision Detection Segment Response"},
    {CIGI2_PACKET_ID_SENSOR_RESPONSE, "Sensor Response"},
    {CIGI2_PACKET_ID_HEIGHT_OF_TERRAIN_RESPONSE, "Height of Terrain Response"},
    {CIGI2_PACKET_ID_COLLISION_DETECTION_VOLUME_RESPONSE, "Collision Detection Volume Response"},
    {CIGI2_PACKET_ID_IMAGE_GENERATOR_MESSAGE, "Image Generator Message"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+1, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+2, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+3, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+4, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+5, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+6, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+7, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+8, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+9, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+10, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+11, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+12, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+13, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+14, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+15, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+16, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+17, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MIN+18, "User Definable"},
    {CIGI2_PACKET_ID_USER_DEFINABLE_MAX, "User Definable"},
    {0, NULL},
};
static value_string_ext cigi2_packet_id_vals_ext = VALUE_STRING_EXT_INIT(cigi2_packet_id_vals);

/* CIGI2 IG Control */
#define CIGI2_PACKET_SIZE_IG_CONTROL 16
static int hf_cigi2_ig_control;
static int hf_cigi2_ig_control_db_number;
static int hf_cigi2_ig_control_ig_mode;
static int hf_cigi2_ig_control_tracking_enable;
static int hf_cigi2_ig_control_boresight;
static int hf_cigi2_ig_control_frame_ctr;
static int hf_cigi2_ig_control_time_tag;

static const value_string cigi2_ig_control_ig_mode_vals[] = {
    {0, "Standby/Reset"},
    {1, "Operate"},
    {2, "Debug"},
    {0, NULL},
};

/* CIGI2 Entity Control */
#define CIGI2_PACKET_SIZE_ENTITY_CONTROL 56
static int hf_cigi2_entity_control;
static int hf_cigi2_entity_control_entity_id;
static int hf_cigi2_entity_control_entity_state;
static int hf_cigi2_entity_control_attach_state;
static int hf_cigi2_entity_control_collision_detect;
static int hf_cigi2_entity_control_effect_state;
static int hf_cigi2_entity_control_type;
static int hf_cigi2_entity_control_parent_id;
static int hf_cigi2_entity_control_opacity;
static int hf_cigi2_entity_control_internal_temp;
static int hf_cigi2_entity_control_roll;
static int hf_cigi2_entity_control_pitch;
static int hf_cigi2_entity_control_heading;
static int hf_cigi2_entity_control_alt;
static int hf_cigi2_entity_control_lat;
static int hf_cigi2_entity_control_lon;

static const value_string cigi2_entity_control_entity_state_vals[] = {
    {0, "Load/Hide"},
    {1, "Load/Show"},
    {2, "Unload"},
    {0, NULL},
};

static const value_string cigi2_entity_control_effect_state_vals[] = {
    {0, "Stop"},
    {1, "Play"},
    {2, "Restart"},
    {0, NULL},
};

/* CIGI2 Component Control */
#define CIGI2_PACKET_SIZE_COMPONENT_CONTROL 20
static int hf_cigi2_component_control;
static int hf_cigi2_component_control_instance_id;
static int hf_cigi2_component_control_component_class;
static int hf_cigi2_component_control_component_id;
static int hf_cigi2_component_control_component_state;
static int hf_cigi2_component_control_component_val1;
static int hf_cigi2_component_control_component_val2;

static const value_string cigi2_component_control_component_class_vals[] = {
    {0, "Entity"},
    {1, "Environment"},
    {2, "View"},
    {3, "View Group"},
    {4, "Sensor"},
    {5, "System"},
    {0, NULL},
};

/* CIGI2 Articulated Parts Control */
#define CIGI2_PACKET_SIZE_ARTICULATED_PARTS_CONTROL 32
static int hf_cigi2_articulated_parts_control;
static int hf_cigi2_articulated_parts_control_entity_id;
static int hf_cigi2_articulated_parts_control_part_id;
static int hf_cigi2_articulated_parts_control_part_state;
static int hf_cigi2_articulated_parts_control_xoff_enable;
static int hf_cigi2_articulated_parts_control_yoff_enable;
static int hf_cigi2_articulated_parts_control_zoff_enable;
static int hf_cigi2_articulated_parts_control_roll_enable;
static int hf_cigi2_articulated_parts_control_pitch_enable;
static int hf_cigi2_articulated_parts_control_yaw_enable;
static int hf_cigi2_articulated_parts_control_x_offset;
static int hf_cigi2_articulated_parts_control_y_offset;
static int hf_cigi2_articulated_parts_control_z_offset;
static int hf_cigi2_articulated_parts_control_roll;
static int hf_cigi2_articulated_parts_control_pitch;
static int hf_cigi2_articulated_parts_control_yaw;

/* CIGI2 Rate Control */
#define CIGI2_PACKET_SIZE_RATE_CONTROL 32
static int hf_cigi2_rate_control;
static int hf_cigi2_rate_control_entity_id;
static int hf_cigi2_rate_control_part_id;
static int hf_cigi2_rate_control_x_rate;
static int hf_cigi2_rate_control_y_rate;
static int hf_cigi2_rate_control_z_rate;
static int hf_cigi2_rate_control_roll_rate;
static int hf_cigi2_rate_control_pitch_rate;
static int hf_cigi2_rate_control_yaw_rate;

/* CIGI2 Environmental Control */
#define CIGI2_PACKET_SIZE_ENVIRONMENT_CONTROL 36
static int hf_cigi2_environment_control;
static int hf_cigi2_environment_control_hour;
static int hf_cigi2_environment_control_minute;
static int hf_cigi2_environment_control_ephemeris_enable;
static int hf_cigi2_environment_control_humidity;
static int hf_cigi2_environment_control_modtran_enable;
static int hf_cigi2_environment_control_date;
static int hf_cigi2_environment_control_air_temp;
static int hf_cigi2_environment_control_global_visibility;
static int hf_cigi2_environment_control_wind_speed;
static int hf_cigi2_environment_control_wind_direction;
static int hf_cigi2_environment_control_pressure;
static int hf_cigi2_environment_control_aerosol;

/* CIGI2 Weather Control */
#define CIGI2_PACKET_SIZE_WEATHER_CONTROL 44
static int hf_cigi2_weather_control;
static int hf_cigi2_weather_control_entity_id;
static int hf_cigi2_weather_control_weather_enable;
static int hf_cigi2_weather_control_scud_enable;
static int hf_cigi2_weather_control_random_winds;
static int hf_cigi2_weather_control_severity;
static int hf_cigi2_weather_control_phenomenon_type;
static int hf_cigi2_weather_control_air_temp;
static int hf_cigi2_weather_control_opacity;
static int hf_cigi2_weather_control_scud_frequency;
static int hf_cigi2_weather_control_coverage;
static int hf_cigi2_weather_control_elevation;
static int hf_cigi2_weather_control_thickness;
static int hf_cigi2_weather_control_transition_band;
static int hf_cigi2_weather_control_wind_speed;
static int hf_cigi2_weather_control_wind_direction;

static const value_string cigi2_weather_control_phenomenon_type_vals[] = {
    {0, "Use Entity ID"},
    {1, "Cloud Layer 1"},
    {2, "Cloud Layer 2"},
    {3, "Ground Fog"},
    {4, "Rain"},
    {5, "Snow"},
    {6, "Sand"},
    {0, NULL},
};

/* CIGI2 View Control */
#define CIGI2_PACKET_SIZE_VIEW_CONTROL 32
static int hf_cigi2_view_control;
static int hf_cigi2_view_control_entity_id;
static int hf_cigi2_view_control_view_id;
static int hf_cigi2_view_control_view_group;
static int hf_cigi2_view_control_xoff_enable;
static int hf_cigi2_view_control_yoff_enable;
static int hf_cigi2_view_control_zoff_enable;
static int hf_cigi2_view_control_roll_enable;
static int hf_cigi2_view_control_pitch_enable;
static int hf_cigi2_view_control_yaw_enable;
static int hf_cigi2_view_control_x_offset;
static int hf_cigi2_view_control_y_offset;
static int hf_cigi2_view_control_z_offset;
static int hf_cigi2_view_control_roll;
static int hf_cigi2_view_control_pitch;
static int hf_cigi2_view_control_yaw;

/* CIGI2 Sensor Control */
#define CIGI2_PACKET_SIZE_SENSOR_CONTROL 24
static int hf_cigi2_sensor_control;
static int hf_cigi2_sensor_control_view_id;
static int hf_cigi2_sensor_control_sensor_enable;
static int hf_cigi2_sensor_control_polarity;
static int hf_cigi2_sensor_control_line_dropout;
static int hf_cigi2_sensor_control_sensor_id;
static int hf_cigi2_sensor_control_track_mode;
static int hf_cigi2_sensor_control_auto_gain;
static int hf_cigi2_sensor_control_track_polarity;
static int hf_cigi2_sensor_control_gain;
static int hf_cigi2_sensor_control_level;
static int hf_cigi2_sensor_control_ac_coupling;
static int hf_cigi2_sensor_control_noise;

static const true_false_string black_white_tfs = {
    "Black",
    "White"
};

static const value_string cigi2_sensor_control_track_mode_vals[] = {
    {0, "Off"},
    {1, "Force Correlate"},
    {2, "Scene"},
    {3, "Target"},
    {4, "Ship"},
    {0, NULL},
};

/* CIGI2 Trajectory Definition */
#define CIGI2_PACKET_SIZE_TRAJECTORY_DEFINITION 16
static int hf_cigi2_trajectory_definition;
static int hf_cigi2_trajectory_definition_entity_id;
static int hf_cigi2_trajectory_definition_acceleration;
static int hf_cigi2_trajectory_definition_retardation;
static int hf_cigi2_trajectory_definition_terminal_velocity;

/* CIGI2 Special Effect Definition */
#define CIGI2_PACKET_SIZE_SPECIAL_EFFECT_DEFINITION 32
static int hf_cigi2_special_effect_definition;
static int hf_cigi2_special_effect_definition_entity_id;
static int hf_cigi2_special_effect_definition_seq_direction;
static int hf_cigi2_special_effect_definition_color_enable;
static int hf_cigi2_special_effect_definition_red;
static int hf_cigi2_special_effect_definition_green;
static int hf_cigi2_special_effect_definition_blue;
static int hf_cigi2_special_effect_definition_x_scale;
static int hf_cigi2_special_effect_definition_y_scale;
static int hf_cigi2_special_effect_definition_z_scale;
static int hf_cigi2_special_effect_definition_time_scale;
static int hf_cigi2_special_effect_definition_spare;
static int hf_cigi2_special_effect_definition_effect_count;
static int hf_cigi2_special_effect_definition_separation;
static int hf_cigi2_special_effect_definition_burst_interval;
static int hf_cigi2_special_effect_definition_duration;

static const true_false_string cigi2_special_effect_definition_seq_direction_tfs = {
    "Backward",
    "Forward"
};

/* CIGI2 View Definition */
#define CIGI2_PACKET_SIZE_VIEW_DEFINITION 32
static int hf_cigi2_view_definition;
static int hf_cigi2_view_definition_view_id;
static int hf_cigi2_view_definition_view_group;
static int hf_cigi2_view_definition_view_type;
static int hf_cigi2_view_definition_pixel_rep;
static int hf_cigi2_view_definition_mirror;
static int hf_cigi2_view_definition_tracker_assign;
static int hf_cigi2_view_definition_near_enable;
static int hf_cigi2_view_definition_far_enable;
static int hf_cigi2_view_definition_left_enable;
static int hf_cigi2_view_definition_right_enable;
static int hf_cigi2_view_definition_top_enable;
static int hf_cigi2_view_definition_bottom_enable;
static int hf_cigi2_view_definition_fov_near;
static int hf_cigi2_view_definition_fov_far;
static int hf_cigi2_view_definition_fov_left;
static int hf_cigi2_view_definition_fov_right;
static int hf_cigi2_view_definition_fov_top;
static int hf_cigi2_view_definition_fov_bottom;

static const value_string cigi2_view_definition_pixel_rep_vals[] = {
    {0, "No Replicate"},
    {1, "1x2 Pixel Replicate"},
    {2, "2x1 Pixel Replicate"},
    {3, "2x2 Pixel Replicate"},
    {4, "TBD"},
    {5, "TBD"},
    {6, "TBD"},
    {0, NULL},
};

static const value_string cigi2_view_definition_mirror_vals[] = {
    {0, "None"},
    {1, "Horizontal"},
    {2, "Vertical"},
    {3, "Horizontal and Vertical"},
    {0, NULL},
};

/* CIGI2 Collision Detection Segment Definition */
#define CIGI2_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_DEFINITION 24
static int hf_cigi2_collision_detection_segment_definition;
static int hf_cigi2_collision_detection_segment_definition_entity_id;
static int hf_cigi2_collision_detection_segment_definition_segment_enable;
static int hf_cigi2_collision_detection_segment_definition_segment_id;
static int hf_cigi2_collision_detection_segment_definition_collision_mask;
static int hf_cigi2_collision_detection_segment_definition_x_start;
static int hf_cigi2_collision_detection_segment_definition_y_start;
static int hf_cigi2_collision_detection_segment_definition_z_start;
static int hf_cigi2_collision_detection_segment_definition_x_end;
static int hf_cigi2_collision_detection_segment_definition_y_end;
static int hf_cigi2_collision_detection_segment_definition_z_end;

/* CIGI2 Collision Detection Volume Definition */
#define CIGI2_PACKET_SIZE_COLLISION_DETECTION_VOLUME_DEFINITION 20
static int hf_cigi2_collision_detection_volume_definition;
static int hf_cigi2_collision_detection_volume_definition_entity_id;
static int hf_cigi2_collision_detection_volume_definition_volume_enable;
static int hf_cigi2_collision_detection_volume_definition_volume_id;
static int hf_cigi2_collision_detection_volume_definition_x_offset;
static int hf_cigi2_collision_detection_volume_definition_y_offset;
static int hf_cigi2_collision_detection_volume_definition_z_offset;
static int hf_cigi2_collision_detection_volume_definition_height;
static int hf_cigi2_collision_detection_volume_definition_width;
static int hf_cigi2_collision_detection_volume_definition_depth;

/* CIGI2 Height Above Terrain Request */
#define CIGI2_PACKET_SIZE_HEIGHT_ABOVE_TERRAIN_REQUEST 32
static int hf_cigi2_height_above_terrain_request;
static int hf_cigi2_height_above_terrain_request_hat_id;
static int hf_cigi2_height_above_terrain_request_alt;
static int hf_cigi2_height_above_terrain_request_lat;
static int hf_cigi2_height_above_terrain_request_lon;

/* CIGI2 Line of Sight Occult Request */
#define CIGI2_PACKET_SIZE_LINE_OF_SIGHT_OCCULT_REQUEST 56
static int hf_cigi2_line_of_sight_occult_request;
static int hf_cigi2_line_of_sight_occult_request_los_id;
static int hf_cigi2_line_of_sight_occult_request_source_alt;
static int hf_cigi2_line_of_sight_occult_request_source_lat;
static int hf_cigi2_line_of_sight_occult_request_source_lon;
static int hf_cigi2_line_of_sight_occult_request_dest_alt;
static int hf_cigi2_line_of_sight_occult_request_dest_lat;
static int hf_cigi2_line_of_sight_occult_request_dest_lon;

/* CIGI2 Line of Sight Range Request */
#define CIGI2_PACKET_SIZE_LINE_OF_SIGHT_RANGE_REQUEST 48
static int hf_cigi2_line_of_sight_range_request;
static int hf_cigi2_line_of_sight_range_request_los_id;
static int hf_cigi2_line_of_sight_range_request_azimuth;
static int hf_cigi2_line_of_sight_range_request_elevation;
static int hf_cigi2_line_of_sight_range_request_min_range;
static int hf_cigi2_line_of_sight_range_request_max_range;
static int hf_cigi2_line_of_sight_range_request_source_alt;
static int hf_cigi2_line_of_sight_range_request_source_lat;
static int hf_cigi2_line_of_sight_range_request_source_lon;

/* CIGI2 Height of Terrain Request */
#define CIGI2_PACKET_SIZE_HEIGHT_OF_TERRAIN_REQUEST 24
static int hf_cigi2_height_of_terrain_request;
static int hf_cigi2_height_of_terrain_request_hot_id;
static int hf_cigi2_height_of_terrain_request_lat;
static int hf_cigi2_height_of_terrain_request_lon;

/* CIGI2 Start of Frame */
#define CIGI2_PACKET_SIZE_START_OF_FRAME 16
static int hf_cigi2_start_of_frame;
static int hf_cigi2_start_of_frame_db_number;
static int hf_cigi2_start_of_frame_ig_status_code;
static int hf_cigi2_start_of_frame_ig_mode;
static int hf_cigi2_start_of_frame_frame_ctr;
static int hf_cigi2_start_of_frame_time_tag;

static const value_string cigi2_start_of_frame_ig_mode_vals[] = {
    {0, "Standby/Reset"},
    {1, "Operate"},
    {2, "Debug"},
    {3, "Off-Line Maintenance"},
    {0, NULL},
};

/* CIGI2 Height Above Terrain Response */
#define CIGI2_PACKET_SIZE_HEIGHT_ABOVE_TERRAIN_RESPONSE 24
static int hf_cigi2_height_above_terrain_response;
static int hf_cigi2_height_above_terrain_response_hat_id;
static int hf_cigi2_height_above_terrain_response_valid;
static int hf_cigi2_height_above_terrain_response_material_type;
static int hf_cigi2_height_above_terrain_response_alt;

/* CIGI2 Line of Sight Response */
#define CIGI2_PACKET_SIZE_LINE_OF_SIGHT_RESPONSE 40
static int hf_cigi2_line_of_sight_response;
static int hf_cigi2_line_of_sight_response_los_id;
static int hf_cigi2_line_of_sight_response_valid;
static int hf_cigi2_line_of_sight_response_occult_response;
static int hf_cigi2_line_of_sight_response_material_type;
static int hf_cigi2_line_of_sight_response_range;
static int hf_cigi2_line_of_sight_response_alt;
static int hf_cigi2_line_of_sight_response_lat;
static int hf_cigi2_line_of_sight_response_lon;

/* CIGI2 Collision Detection Segment Response */
#define CIGI2_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_RESPONSE 24
static int hf_cigi2_collision_detection_segment_response;
static int hf_cigi2_collision_detection_segment_response_entity_id;
static int hf_cigi2_collision_detection_segment_response_segment_id;
static int hf_cigi2_collision_detection_segment_response_contact;
static int hf_cigi2_collision_detection_segment_response_contacted_entity;
static int hf_cigi2_collision_detection_segment_response_material_type;
static int hf_cigi2_collision_detection_segment_response_collision_x;
static int hf_cigi2_collision_detection_segment_response_collision_y;
static int hf_cigi2_collision_detection_segment_response_collision_z;

static const true_false_string cigi2_collision_detection_segment_response_contact_tfs = {
    "Contact with a defined entity",
    "Contact with a non-entity surface"
};

/* CIGI2 Sensor Response */
#define CIGI2_PACKET_SIZE_SENSOR_RESPONSE 12
static int hf_cigi2_sensor_response;
static int hf_cigi2_sensor_response_view_id;
static int hf_cigi2_sensor_response_status;
static int hf_cigi2_sensor_response_sensor_id;
static int hf_cigi2_sensor_response_x_offset;
static int hf_cigi2_sensor_response_y_offset;
static int hf_cigi2_sensor_response_x_size;
static int hf_cigi2_sensor_response_y_size;

static const value_string cigi2_sensor_response_status_vals[] = {
    {0, "Searching for Target"},
    {1, "Tracking"},
    {2, "Impending Breaklock"},
    {3, "Breaklock"},
    {0, NULL},
};

/* CIGI2 Height of Terrain Response */
#define CIGI2_PACKET_SIZE_HEIGHT_OF_TERRAIN_RESPONSE 24
static int hf_cigi2_height_of_terrain_response;
static int hf_cigi2_height_of_terrain_response_hot_id;
static int hf_cigi2_height_of_terrain_response_valid;
static int hf_cigi2_height_of_terrain_response_material_type;
static int hf_cigi2_height_of_terrain_response_alt;

/* CIGI2 Collision Detection Volume Response */
#define CIGI2_PACKET_SIZE_COLLISION_DETECTION_VOLUME_RESPONSE 8
static int hf_cigi2_collision_detection_volume_response;
static int hf_cigi2_collision_detection_volume_response_entity_id;
static int hf_cigi2_collision_detection_volume_response_volume_id;
static int hf_cigi2_collision_detection_volume_response_contact;
static int hf_cigi2_collision_detection_volume_response_contact_entity;

static const true_false_string cigi2_collision_detection_volume_response_contact_tfs = {
    "Contact with a defined entity",
    "Contact with a non-entity surface"
};

/* CIGI2 Image Generator Message */
static int hf_cigi2_image_generator_message;
static int hf_cigi2_image_generator_message_id;
static int hf_cigi2_image_generator_message_message;

/* CIGI2 User Definable */
static int hf_cigi2_user_definable;


/*** Fields for CIGI3 ***/

static int hf_cigi3_byte_swap;

#define CIGI3_BYTE_SWAP_BIG_ENDIAN    0x8000
#define CIGI3_BYTE_SWAP_LITTLE_ENDIAN 0x0080
static const value_string cigi3_byte_swap_vals[] = {
    {CIGI3_BYTE_SWAP_BIG_ENDIAN, "Big-Endian"},
    {CIGI3_BYTE_SWAP_LITTLE_ENDIAN, "Little-Endian"},
    {0, NULL},
};

/* CIGI3 Packet ID */
static int hf_cigi3_packet_id;
#define CIGI3_PACKET_ID_IG_CONTROL                                 1
#define CIGI3_PACKET_ID_ENTITY_CONTROL                             2
#define CIGI3_PACKET_ID_CONFORMAL_CLAMPED_ENTITY_CONTROL           3
#define CIGI3_PACKET_ID_COMPONENT_CONTROL                          4
#define CIGI3_PACKET_ID_SHORT_COMPONENT_CONTROL                    5
#define CIGI3_PACKET_ID_ARTICULATED_PART_CONTROL                   6
#define CIGI3_PACKET_ID_SHORT_ARTICULATED_PART_CONTROL             7
#define CIGI3_PACKET_ID_RATE_CONTROL                               8
#define CIGI3_PACKET_ID_CELESTIAL_SPHERE_CONTROL                   9
#define CIGI3_PACKET_ID_ATMOSPHERE_CONTROL                        10
#define CIGI3_PACKET_ID_ENVIRONMENTAL_REGION_CONTROL              11
#define CIGI3_PACKET_ID_WEATHER_CONTROL                           12
#define CIGI3_PACKET_ID_MARITIME_SURFACE_CONDITIONS_CONTROL       13
#define CIGI3_PACKET_ID_WAVE_CONTROL                              14
#define CIGI3_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL    15
#define CIGI3_PACKET_ID_VIEW_CONTROL                              16
#define CIGI3_PACKET_ID_SENSOR_CONTROL                            17
#define CIGI3_PACKET_ID_MOTION_TRACKER_CONTROL                    18
#define CIGI3_PACKET_ID_EARTH_REFERENCE_MODEL_DEFINITION          19
#define CIGI3_PACKET_ID_TRAJECTORY_DEFINITION                     20
#define CIGI3_PACKET_ID_VIEW_DEFINITION                           21
#define CIGI3_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION    22
#define CIGI3_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION     23
#define CIGI3_PACKET_ID_HAT_HOT_REQUEST                           24
#define CIGI3_PACKET_ID_LINE_OF_SIGHT_SEGMENT_REQUEST             25
#define CIGI3_PACKET_ID_LINE_OF_SIGHT_VECTOR_REQUEST              26
#define CIGI3_PACKET_ID_POSITION_REQUEST                          27
#define CIGI3_PACKET_ID_ENVIRONMENTAL_CONDITIONS_REQUEST          28
#define CIGI3_PACKET_ID_SYMBOL_SURFACE_DEFINITION                 29
#define CIGI3_PACKET_ID_SYMBOL_TEXT_DEFINITION                    30
#define CIGI3_PACKET_ID_SYMBOL_CIRCLE_DEFINITION                  31
#define CIGI3_PACKET_ID_SYMBOL_LINE_DEFINITION                    32
#define CIGI3_PACKET_ID_SYMBOL_CLONE                              33
#define CIGI3_PACKET_ID_SYMBOL_CONTROL                            34
#define CIGI3_PACKET_ID_SHORT_SYMBOL_CONTROL                      35
#define CIGI3_PACKET_ID_START_OF_FRAME                           101
#define CIGI3_PACKET_ID_HAT_HOT_RESPONSE                         102
#define CIGI3_PACKET_ID_HAT_HOT_EXTENDED_RESPONSE                103
#define CIGI3_PACKET_ID_LINE_OF_SIGHT_RESPONSE                   104
#define CIGI3_PACKET_ID_LINE_OF_SIGHT_EXTENDED_RESPONSE          105
#define CIGI3_PACKET_ID_SENSOR_RESPONSE                          106
#define CIGI3_PACKET_ID_SENSOR_EXTENDED_RESPONSE                 107
#define CIGI3_PACKET_ID_POSITION_RESPONSE                        108
#define CIGI3_PACKET_ID_WEATHER_CONDITIONS_RESPONSE              109
#define CIGI3_PACKET_ID_AEROSOL_CONCENTRATION_RESPONSE           110
#define CIGI3_PACKET_ID_MARITIME_SURFACE_CONDITIONS_RESPONSE     111
#define CIGI3_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE  112
#define CIGI3_PACKET_ID_COLLISION_DETECTION_SEGMENT_NOTIFICATION 113
#define CIGI3_PACKET_ID_COLLISION_DETECTION_VOLUME_NOTIFICATION  114
#define CIGI3_PACKET_ID_ANIMATION_STOP_NOTIFICATION              115
#define CIGI3_PACKET_ID_EVENT_NOTIFICATION                       116
#define CIGI3_PACKET_ID_IMAGE_GENERATOR_MESSAGE                  117
#define CIGI3_PACKET_ID_USER_DEFINED_MIN                         201
#define CIGI3_PACKET_ID_USER_DEFINED_MAX                         255
static const value_string cigi3_packet_id_vals[] = {
    {CIGI3_PACKET_ID_IG_CONTROL, "IG Control"},
    {CIGI3_PACKET_ID_ENTITY_CONTROL, "Entity Control"},
    {CIGI3_PACKET_ID_CONFORMAL_CLAMPED_ENTITY_CONTROL, "Conformal Clamped Entity Control"},
    {CIGI3_PACKET_ID_COMPONENT_CONTROL, "Component Control"},
    {CIGI3_PACKET_ID_SHORT_COMPONENT_CONTROL, "Short Component Control"},
    {CIGI3_PACKET_ID_ARTICULATED_PART_CONTROL, "Articulated Part Control"},
    {CIGI3_PACKET_ID_SHORT_ARTICULATED_PART_CONTROL, "Short Articulated Part Control"},
    {CIGI3_PACKET_ID_RATE_CONTROL, "Rate Control"},
    {CIGI3_PACKET_ID_CELESTIAL_SPHERE_CONTROL, "Celestial Sphere Control"},
    {CIGI3_PACKET_ID_ATMOSPHERE_CONTROL, "Atmosphere Control"},
    {CIGI3_PACKET_ID_ENVIRONMENTAL_REGION_CONTROL, "Environmental Region Control"},
    {CIGI3_PACKET_ID_WEATHER_CONTROL, "Weather Control"},
    {CIGI3_PACKET_ID_MARITIME_SURFACE_CONDITIONS_CONTROL, "Maritime Surface Conditions Control"},
    {CIGI3_PACKET_ID_WAVE_CONTROL, "Wave Control"},
    {CIGI3_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL, "Terrestrial Surface Conditions Control"},
    {CIGI3_PACKET_ID_VIEW_CONTROL, "View Control"},
    {CIGI3_PACKET_ID_SENSOR_CONTROL, "Sensor Control"},
    {CIGI3_PACKET_ID_MOTION_TRACKER_CONTROL, "Motion Tracker Control"},
    {CIGI3_PACKET_ID_EARTH_REFERENCE_MODEL_DEFINITION, "Earth Reference Model Definition"},
    {CIGI3_PACKET_ID_TRAJECTORY_DEFINITION, "Trajectory Definition"},
    {CIGI3_PACKET_ID_VIEW_DEFINITION, "View Definition"},
    {CIGI3_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION, "Collision Detection Segment Definition"},
    {CIGI3_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION, "Collision Detection Volume Definition"},
    {CIGI3_PACKET_ID_HAT_HOT_REQUEST, "HAT/HOT Request"},
    {CIGI3_PACKET_ID_LINE_OF_SIGHT_SEGMENT_REQUEST, "Line of Sight Segment Request"},
    {CIGI3_PACKET_ID_LINE_OF_SIGHT_VECTOR_REQUEST, "Line of Sight Vector Request"},
    {CIGI3_PACKET_ID_POSITION_REQUEST, "Position Request"},
    {CIGI3_PACKET_ID_ENVIRONMENTAL_CONDITIONS_REQUEST, "Environmental Conditions Request"},
    {CIGI3_PACKET_ID_SYMBOL_SURFACE_DEFINITION, "Symbol Surface Definition"},
    {CIGI3_PACKET_ID_SYMBOL_TEXT_DEFINITION, "Symbol Text Definition"},
    {CIGI3_PACKET_ID_SYMBOL_CIRCLE_DEFINITION, "Symbol Circle Definition"},
    {CIGI3_PACKET_ID_SYMBOL_LINE_DEFINITION, "Symbol Line Definition"},
    {CIGI3_PACKET_ID_SYMBOL_CLONE, "Symbol Clone"},
    {CIGI3_PACKET_ID_SYMBOL_CONTROL, "Symbol Control"},
    {CIGI3_PACKET_ID_SHORT_SYMBOL_CONTROL, "Short Symbol Control"},
    {CIGI3_PACKET_ID_START_OF_FRAME, "Start of Frame"},
    {CIGI3_PACKET_ID_HAT_HOT_RESPONSE, "HAT/HOT Response"},
    {CIGI3_PACKET_ID_HAT_HOT_EXTENDED_RESPONSE, "HAT/HOT Extended Response"},
    {CIGI3_PACKET_ID_LINE_OF_SIGHT_RESPONSE, "Line of Sight Response"},
    {CIGI3_PACKET_ID_LINE_OF_SIGHT_EXTENDED_RESPONSE, "Line of Sight Extended Response"},
    {CIGI3_PACKET_ID_SENSOR_RESPONSE, "Sensor Response"},
    {CIGI3_PACKET_ID_SENSOR_EXTENDED_RESPONSE, "Sensor Extended Response"},
    {CIGI3_PACKET_ID_POSITION_RESPONSE, "Position Response"},
    {CIGI3_PACKET_ID_WEATHER_CONDITIONS_RESPONSE, "Weather Conditions Response"},
    {CIGI3_PACKET_ID_AEROSOL_CONCENTRATION_RESPONSE, "Aerosol Concentration Response"},
    {CIGI3_PACKET_ID_MARITIME_SURFACE_CONDITIONS_RESPONSE, "Maritime Surface Conditions Response"},
    {CIGI3_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE, "Terrestrial Surface Conditions Response"},
    {CIGI3_PACKET_ID_COLLISION_DETECTION_SEGMENT_NOTIFICATION, "Collision Detection Segment Notification"},
    {CIGI3_PACKET_ID_COLLISION_DETECTION_VOLUME_NOTIFICATION, "Collision Detection Volume Notification"},
    {CIGI3_PACKET_ID_ANIMATION_STOP_NOTIFICATION, "Animation Stop Notification"},
    {CIGI3_PACKET_ID_EVENT_NOTIFICATION, "Event Notification"},
    {CIGI3_PACKET_ID_IMAGE_GENERATOR_MESSAGE, "Image Generator Message"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+1, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+2, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+3, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+4, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+5, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+6, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+7, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+8, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+9, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+10, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+11, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+12, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+13, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+14, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+15, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+16, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+17, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+18, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+19, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+20, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+21, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+22, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+23, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+24, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+25, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+26, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+27, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+28, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+29, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+30, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+31, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+32, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+33, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+34, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+35, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+36, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+37, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+38, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+39, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+40, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+41, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+42, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+43, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+44, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+45, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+46, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+47, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+48, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+49, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+50, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+51, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+52, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MIN+53, "User-Defined Data"},
    {CIGI3_PACKET_ID_USER_DEFINED_MAX, "User-Defined Data"},
    {0, NULL},
};
static value_string_ext cigi3_packet_id_vals_ext = VALUE_STRING_EXT_INIT(cigi3_packet_id_vals);

/* CIGI3 IG Control */
#define CIGI3_PACKET_SIZE_IG_CONTROL 16
static int hf_cigi3_ig_control;
static int hf_cigi3_ig_control_db_number;
static int hf_cigi3_ig_control_ig_mode;
static int hf_cigi3_ig_control_timestamp_valid;
static int hf_cigi3_ig_control_frame_ctr;
static int hf_cigi3_ig_control_timestamp;

static const value_string cigi3_ig_control_ig_mode_vals[] = {
    {0, "Reset/Standby"},
    {1, "Operate"},
    {2, "Debug"},
    {0, NULL},
};

/* CIGI3_2 IG Control */
#define CIGI3_2_PACKET_SIZE_IG_CONTROL 24
static int hf_cigi3_2_ig_control_minor_version;
static int hf_cigi3_2_ig_control_host_frame_number;
static int hf_cigi3_2_ig_control_last_ig_frame_number;

/* CIGI3_3 IG Control */
#define CIGI3_3_PACKET_SIZE_IG_CONTROL 24
static int hf_cigi3_3_ig_control_extrapolation_enable;

/* CIGI3 Entity Control */
#define CIGI3_PACKET_SIZE_ENTITY_CONTROL 48
static int hf_cigi3_entity_control;
static int hf_cigi3_entity_control_entity_id;
static int hf_cigi3_entity_control_entity_state;
static int hf_cigi3_entity_control_attach_state;
static int hf_cigi3_entity_control_collision_detection_request;
static int hf_cigi3_entity_control_inherit_alpha;
static int hf_cigi3_entity_control_ground_ocean_clamp;
static int hf_cigi3_entity_control_animation_direction;
static int hf_cigi3_entity_control_animation_loop_mode;
static int hf_cigi3_entity_control_animation_state;
static int hf_cigi3_entity_control_alpha;
static int hf_cigi3_entity_control_entity_type;
static int hf_cigi3_entity_control_parent_id;
static int hf_cigi3_entity_control_roll;
static int hf_cigi3_entity_control_pitch;
static int hf_cigi3_entity_control_yaw;
static int hf_cigi3_entity_control_lat_xoff;
static int hf_cigi3_entity_control_lon_yoff;
static int hf_cigi3_entity_control_alt_zoff;

static const value_string cigi3_entity_control_entity_state_vals[] = {
    {0, "Inactive/Standby"},
    {1, "Active"},
    {2, "Destroyed"},
    {0, NULL},
};

static const true_false_string cigi3_entity_control_collision_detection_request_tfs = {
    "Request",
    "No Request"
};

static const true_false_string inherited_not_inherited_tfs = {
    "Inherited",
    "Not Inherited"
};

static const value_string cigi3_entity_control_ground_ocean_clamp_vals[] = {
    {0, "No Clamp"},
    {1, "Non-Conformal"},
    {2, "Conformal"},
    {0, NULL},
};

static const true_false_string cigi3_entity_control_animation_direction_tfs = {
    "Backward",
    "Forward"
};

static const true_false_string cigi3_entity_control_animation_loop_mode_tfs = {
    "Continuous",
    "One-Shot"
};

static const value_string cigi3_entity_control_animation_state_vals[] = {
    {0, "Stop"},
    {1, "Pause"},
    {2, "Play"},
    {3, "Continue"},
    {0, NULL},
};

/* CIGI3_3 Entity Control */
static int hf_cigi3_3_entity_control_extrapolation_enable;

/* CIGI4 Entity Control */
/* Subset of previous packet by this name containing parameters expected to
 * change infrequently.*/
#define CIGI4_PACKET_SIZE_ENTITY_CONTROL                            16
static int hf_cigi4_entity_control;
static int hf_cigi4_entity_control_entity_state;
static int hf_cigi4_entity_control_collision_reporting_enable;
static int hf_cigi4_entity_control_inherit_alpha;
static int hf_cigi4_entity_control_smooting_enable;
static int hf_cigi4_entity_control_extended_entity_type;
static int hf_cigi4_entity_control_alpha;
static int hf_cigi4_entity_control_entity_id;
static int hf_cigi4_entity_control_entity_kind;
static int hf_cigi4_entity_control_entity_domain;
static int hf_cigi4_entity_control_entity_country;
static int hf_cigi4_entity_control_entity_category;
static int hf_cigi4_entity_control_entity_subcategory;
static int hf_cigi4_entity_control_entity_specific;
static int hf_cigi4_entity_control_entity_extra;

static const value_string cigi4_entity_control_entity_state_vals[] = {
    {0, "Inactive/Standby"},
    {1, "Active"},
    {2, "Destroyed"},
    {0, NULL},
};

static const true_false_string cigi4_entity_control_inherit_alpha_tfs = {
    "Not Inherited",
    "Inherited"
};

static const true_false_string tfs_entity_control_extended_entity_type = {
    "Short",
    "Extended"
};


#define CIGI4_PACKET_SIZE_ANIMATION_CONTROL                         16
static int hf_cigi4_animation_control;
static int hf_cigi4_animation_control_state;
static int hf_cigi4_animation_control_frame_position_reset;
static int hf_cigi4_animation_control_loop_mode;
static int hf_cigi4_animation_control_inherit_alpha;
static int hf_cigi4_animation_control_alpha;
static int hf_cigi4_animation_control_entity_id;
static int hf_cigi4_animation_control_animation_id;
static int hf_cigi4_animation_control_animation_speed;

static const true_false_string cigi4_animation_control_state_tfs = {
    "Stop",
    "Play"
};

static const true_false_string cigi4_animation_control_state_positon_reset_tfs = {
    "Continue",
    "Reset"
};

static const true_false_string cigi4_animation_control_state_loop_mode = {
    "One-Shot",
    "Continuous"
};


static const true_false_string cigi4_animation_control_state_inherit_alpha = {
    "Not Inherited",
    "Inherited"
};



/* CIGI3 Conformal Clamped Entity Control */
#define CIGI3_PACKET_SIZE_CONFORMAL_CLAMPED_ENTITY_CONTROL 24
static int hf_cigi3_conformal_clamped_entity_control;
static int hf_cigi3_conformal_clamped_entity_control_entity_id;
static int hf_cigi3_conformal_clamped_entity_control_yaw;
static int hf_cigi3_conformal_clamped_entity_control_lat;
static int hf_cigi3_conformal_clamped_entity_control_lon;

/* CIGI3 Component Control */
#define CIGI3_PACKET_SIZE_COMPONENT_CONTROL 32
static int hf_cigi3_component_control;
static int hf_cigi3_component_control_component_id;
static int hf_cigi3_component_control_instance_id;
static int hf_cigi3_component_control_component_class;
static int hf_cigi3_component_control_component_state;
static int hf_cigi3_component_control_data_1;
static int hf_cigi3_component_control_data_2;
static int hf_cigi3_component_control_data_3;
static int hf_cigi3_component_control_data_4;
static int hf_cigi3_component_control_data_5;
static int hf_cigi3_component_control_data_6;

static const value_string cigi3_component_control_component_class_vals[] = {
    {0, "Entity"},
    {1, "View"},
    {2, "View Group"},
    {3, "Sensor"},
    {4, "Regional Sea Surface"},
    {5, "Regional Terrain Surface"},
    {6, "Regional Layered Weather"},
    {7, "Global Sea Surface"},
    {8, "Global Terrain Surface"},
    {9, "Global Layered Weather"},
    {10, "Atmosphere"},
    {11, "Celestial Sphere"},
    {12, "Event"},
    {13, "System"},
    {0, NULL},
};

/* CIGI3_3 Component Control */
static int hf_cigi3_3_component_control_component_class;

static const value_string cigi3_3_component_control_component_class_vals[] = {
    {0, "Entity"},
    {1, "View"},
    {2, "View Group"},
    {3, "Sensor"},
    {4, "Regional Sea Surface"},
    {5, "Regional Terrain Surface"},
    {6, "Regional Layered Weather"},
    {7, "Global Sea Surface"},
    {8, "Global Terrain Surface"},
    {9, "Global Layered Weather"},
    {10, "Atmosphere"},
    {11, "Celestial Sphere"},
    {12, "Event"},
    {13, "System"},
    {14, "Symbol Surface"},
    {15, "Symbol"},
    {0, NULL},
};

/* CIGI3 Short Component Control */
#define CIGI3_PACKET_SIZE_SHORT_COMPONENT_CONTROL 16
static int hf_cigi3_short_component_control;
static int hf_cigi3_short_component_control_component_id;
static int hf_cigi3_short_component_control_instance_id;
static int hf_cigi3_short_component_control_component_class;
static int hf_cigi3_short_component_control_component_state;
static int hf_cigi3_short_component_control_data_1;
static int hf_cigi3_short_component_control_data_2;

static const value_string cigi3_short_component_control_component_class_vals[] = {
    {0, "Entity"},
    {1, "View"},
    {2, "View Group"},
    {3, "Sensor"},
    {4, "Regional Sea Surface"},
    {5, "Regional Terrain Surface"},
    {6, "Regional Layered Weather"},
    {7, "Global Sea Surface"},
    {8, "Global Terrain Surface"},
    {9, "Global Layered Weather"},
    {10, "Atmosphere"},
    {11, "Celestial Sphere"},
    {12, "Event"},
    {13, "System"},
    {0, NULL},
};

/* CIGI3_3 Short Component Control */
static int hf_cigi3_3_short_component_control_component_class;

static const value_string cigi3_3_short_component_control_component_class_vals[] = {
    {0, "Entity"},
    {1, "View"},
    {2, "View Group"},
    {3, "Sensor"},
    {4, "Regional Sea Surface"},
    {5, "Regional Terrain Surface"},
    {6, "Regional Layered Weather"},
    {7, "Global Sea Surface"},
    {8, "Global Terrain Surface"},
    {9, "Global Layered Weather"},
    {10, "Atmosphere"},
    {11, "Celestial Sphere"},
    {12, "Event"},
    {13, "System"},
    {14, "Symbol Surface"},
    {15, "Symbol"},
    {0, NULL},
};

/* CIGI3 Articulated Part Control */
#define CIGI3_PACKET_SIZE_ARTICULATED_PART_CONTROL 32
static int hf_cigi3_articulated_part_control;
static int hf_cigi3_articulated_part_control_entity_id;
static int hf_cigi3_articulated_part_control_part_id;
static int hf_cigi3_articulated_part_control_part_enable;
static int hf_cigi3_articulated_part_control_xoff_enable;
static int hf_cigi3_articulated_part_control_yoff_enable;
static int hf_cigi3_articulated_part_control_zoff_enable;
static int hf_cigi3_articulated_part_control_roll_enable;
static int hf_cigi3_articulated_part_control_pitch_enable;
static int hf_cigi3_articulated_part_control_yaw_enable;
static int hf_cigi3_articulated_part_control_xoff;
static int hf_cigi3_articulated_part_control_yoff;
static int hf_cigi3_articulated_part_control_zoff;
static int hf_cigi3_articulated_part_control_roll;
static int hf_cigi3_articulated_part_control_pitch;
static int hf_cigi3_articulated_part_control_yaw;

/* CIGI4 Articulated Part Control */
#define CIGI4_PACKET_SIZE_ARTICULATED_PART_CONTROL 32
static int hf_cigi4_articulated_part_control_part_enable_flags;

static int ett_cigi4_articulated_part_control_part_enable_flags;


/* CIGI3 Short Articulated Part Control */
#define CIGI3_PACKET_SIZE_SHORT_ARTICULATED_PART_CONTROL 16
static int hf_cigi3_short_articulated_part_control;
static int hf_cigi3_short_articulated_part_control_entity_id;
static int hf_cigi3_short_articulated_part_control_part_id_1;
static int hf_cigi3_short_articulated_part_control_part_id_2;
static int hf_cigi3_short_articulated_part_control_dof_select_1;
static int hf_cigi3_short_articulated_part_control_dof_select_2;
static int hf_cigi3_short_articulated_part_control_part_enable_1;
static int hf_cigi3_short_articulated_part_control_part_enable_2;
static int hf_cigi3_short_articulated_part_control_dof_1;
static int hf_cigi3_short_articulated_part_control_dof_2;

static const value_string cigi3_short_articulated_part_control_dof_select_vals[] = {
    {0, "Not Used"},
    {1, "X Offset"},
    {2, "Y Offset"},
    {3, "Z Offset"},
    {4, "Yaw"},
    {5, "Pitch"},
    {6, "Roll"},
    {0, NULL},
};

/* CIGI4 Short Articulated Part Control */
#define CIGI4_PACKET_SIZE_SHORT_ARTICULATED_PART_CONTROL            24
static int hf_cigi4_short_articulated_part_control_part_enable_flags;

static int ett_cigi4_short_articulated_part_control_part_enable_flags;

/* CIGI3 Rate Control */
#define CIGI3_PACKET_SIZE_RATE_CONTROL 32
static int hf_cigi3_rate_control;
static int hf_cigi3_rate_control_entity_id;
static int hf_cigi3_rate_control_part_id;
static int hf_cigi3_rate_control_apply_to_part;
static int hf_cigi3_2_rate_control_coordinate_system;
static int hf_cigi3_rate_control_x_rate;
static int hf_cigi3_rate_control_y_rate;
static int hf_cigi3_rate_control_z_rate;
static int hf_cigi3_rate_control_roll_rate;
static int hf_cigi3_rate_control_pitch_rate;
static int hf_cigi3_rate_control_yaw_rate;

static const true_false_string local_worldparent_tfs = {
    "Local",
    "World/Parent"
};

/* CIGI4 Velocity Control */
/* Rate Control packet renamed. */
#define CIGI4_PACKET_SIZE_VELOCITY_CONTROL       32

static int  hf_cigi4_velocity_control;
static int  hf_cigi4_velocity_control_entity_id;
static int  hf_cigi4_velocity_control_part_id;
static int  hf_cigi4_velocity_control_flags;
static int  hf_cigi4_velocity_control_apply_to_part;
static int  hf_cigi4_velocity_control_coordinate_system;
static int  hf_cigi4_velocity_control_x_rate;
static int  hf_cigi4_velocity_control_y_rate;
static int  hf_cigi4_velocity_control_z_rate;
static int  hf_cigi4_velocity_control_roll_rate;
static int  hf_cigi4_velocity_control_pitch_rate;
static int  hf_cigi4_velocity_control_yaw_rate;

static int  ett_cigi4_velocity_control_flags;


/* CIGI3 Celestial Sphere Control */
#define CIGI3_PACKET_SIZE_CELESTIAL_SPHERE_CONTROL 16
static int hf_cigi3_celestial_sphere_control;
static int hf_cigi3_celestial_sphere_control_hour;
static int hf_cigi3_celestial_sphere_control_minute;
static int hf_cigi3_celestial_sphere_control_ephemeris_enable;
static int hf_cigi3_celestial_sphere_control_sun_enable;
static int hf_cigi3_celestial_sphere_control_moon_enable;
static int hf_cigi3_celestial_sphere_control_star_enable;
static int hf_cigi3_celestial_sphere_control_date_time_valid;
static int hf_cigi3_celestial_sphere_control_date;
static int hf_cigi3_celestial_sphere_control_star_intensity;

/* CIGI4 Celestial Sphere Control */
#define CIGI4_PACKET_SIZE_CELESTIAL_SPHERE_CONTROL 24
static int hf_cigi4_celestial_sphere_control_enable_flags;
static int hf_cigi4_celestial_sphere_control_seconds;
static int hf_cigi4_celestial_sphere_control_date;

static int ett_cigi4_celestial_sphere_control_flags;

/* CIGI3 Atmosphere Control */
#define CIGI3_PACKET_SIZE_ATMOSPHERE_CONTROL 32
static int hf_cigi3_atmosphere_control;
static int hf_cigi3_atmosphere_control_atmospheric_model_enable;
static int hf_cigi3_atmosphere_control_humidity;
static int hf_cigi3_atmosphere_control_air_temp;
static int hf_cigi3_atmosphere_control_visibility_range;
static int hf_cigi3_atmosphere_control_horiz_wind;
static int hf_cigi3_atmosphere_control_vert_wind;
static int hf_cigi3_atmosphere_control_wind_direction;
static int hf_cigi3_atmosphere_control_barometric_pressure;

/* CIGI4 Atmosphere Control */
#define CIGI4_PACKET_SIZE_ATMOSPHERE_CONTROL 32

/* CIGI3 Environmental Region Control */
#define CIGI3_PACKET_SIZE_ENVIRONMENTAL_REGION_CONTROL 48
static int hf_cigi3_environmental_region_control;
static int hf_cigi3_environmental_region_control_region_id;
static int hf_cigi3_environmental_region_control_region_state;
static int hf_cigi3_environmental_region_control_merge_weather;
static int hf_cigi3_environmental_region_control_merge_aerosol;
static int hf_cigi3_environmental_region_control_merge_maritime;
static int hf_cigi3_environmental_region_control_merge_terrestrial;
static int hf_cigi3_environmental_region_control_lat;
static int hf_cigi3_environmental_region_control_lon;
static int hf_cigi3_environmental_region_control_size_x;
static int hf_cigi3_environmental_region_control_size_y;
static int hf_cigi3_environmental_region_control_corner_radius;
static int hf_cigi3_environmental_region_control_rotation;
static int hf_cigi3_environmental_region_control_transition_perimeter;

static const value_string cigi3_environmental_region_control_region_state_vals[] = {
    {0, "Inactive"},
    {1, "Active"},
    {2, "Destroyed"},
    {0, NULL},
};

static const true_false_string cigi3_environmental_region_control_merge_properties_tfs = {
    "Merge",
    "Use Last"
};


/* CIGI4 Environmental Region Control */
#define CIGI4_PACKET_SIZE_ENVIRONMENTAL_REGION_CONTROL 48

/* CIGI3 Weather Control */
#define CIGI3_PACKET_SIZE_WEATHER_CONTROL 56
static int hf_cigi3_weather_control;
static int hf_cigi3_weather_control_entity_region_id;
static int hf_cigi3_weather_control_layer_id;
static int hf_cigi3_weather_control_humidity;
static int hf_cigi3_weather_control_weather_enable;
static int hf_cigi3_weather_control_scud_enable;
static int hf_cigi3_weather_control_random_winds_enable;
static int hf_cigi3_weather_control_random_lightning_enable;
static int hf_cigi3_weather_control_cloud_type;
static int hf_cigi3_weather_control_scope;
static int hf_cigi3_weather_control_severity;
static int hf_cigi3_weather_control_air_temp;
static int hf_cigi3_weather_control_visibility_range;
static int hf_cigi3_weather_control_scud_frequency;
static int hf_cigi3_weather_control_coverage;
static int hf_cigi3_weather_control_base_elevation;
static int hf_cigi3_weather_control_thickness;
static int hf_cigi3_weather_control_transition_band;
static int hf_cigi3_weather_control_horiz_wind;
static int hf_cigi3_weather_control_vert_wind;
static int hf_cigi3_weather_control_wind_direction;
static int hf_cigi3_weather_control_barometric_pressure;
static int hf_cigi3_weather_control_aerosol_concentration;

static const value_string cigi3_weather_control_layer_id_vals[] = {
    {0, "Ground Fog"},
    {1, "Cloud Layer 1"},
    {2, "Cloud Layer 2"},
    {3, "Cloud Layer 3"},
    {4, "Rain"},
    {5, "Snow"},
    {6, "Sleet"},
    {7, "Hail"},
    {8, "Sand"},
    {9, "Dust"},
    {0, NULL},
};

static const value_string cigi3_weather_control_cloud_type_vals[] = {
    {0, "None"},
    {1, "Altocumulus"},
    {2, "Altostratus"},
    {3, "Cirrocumulus"},
    {4, "Cirrostratus"},
    {5, "Cirrus"},
    {6, "Cumulonimbus"},
    {7, "Cumulus"},
    {8, "Nimbostratus"},
    {9, "Stratocumulus"},
    {10, "Stratus"},
    {11, "Other"},
    {12, "Other"},
    {13, "Other"},
    {14, "Other"},
    {15, "Other"},
    {0, NULL},
};

static const value_string cigi3_weather_control_scope_vals[] = {
    {0, "Global"},
    {1, "Regional"},
    {2, "Entity"},
    {0, NULL},
};


/* CIGI4 Weather Control */
#define CIGI4_PACKET_SIZE_WEATHER_CONTROL 72
static int hf_cigi4_weather_control_flags;
static int hf_cigi4_weather_control_top_scud_enable;
static int hf_cigi4_weather_control_top_scud_freq;
static int hf_cigi4_weather_control_top_transition_band;

/* CIGI3 Maritime Surface Conditions Control */
#define CIGI3_PACKET_SIZE_MARITIME_SURFACE_CONDITIONS_CONTROL 24
static int hf_cigi3_maritime_surface_conditions_control;
static int hf_cigi3_maritime_surface_conditions_control_entity_region_id;
static int hf_cigi3_maritime_surface_conditions_control_surface_conditions_enable;
static int hf_cigi3_maritime_surface_conditions_control_whitecap_enable;
static int hf_cigi3_maritime_surface_conditions_control_scope;
static int hf_cigi3_maritime_surface_conditions_control_sea_surface_height;
static int hf_cigi3_maritime_surface_conditions_control_surface_water_temp;
static int hf_cigi3_maritime_surface_conditions_control_surface_clarity;

static const value_string cigi3_maritime_surface_conditions_control_scope_vals[] = {
    {0, "Global"},
    {1, "Regional"},
    {2, "Entity"},
    {0, NULL},
};

/* CIGI4 Maritime Surface Conditions Control */
#define CIGI4_PACKET_SIZE_MARITIME_SURFACE_CONDITIONS_CONTROL 24

/* CIGI3 Wave Control */
#define CIGI3_PACKET_SIZE_WAVE_CONTROL 32
static int hf_cigi3_wave_control;
static int hf_cigi3_wave_control_entity_region_id;
static int hf_cigi3_wave_control_wave_id;
static int hf_cigi3_wave_control_wave_enable;
static int hf_cigi3_wave_control_scope;
static int hf_cigi3_wave_control_breaker_type;
static int hf_cigi3_wave_control_height;
static int hf_cigi3_wave_control_wavelength;
static int hf_cigi3_wave_control_period;
static int hf_cigi3_wave_control_direction;
static int hf_cigi3_wave_control_phase_offset;
static int hf_cigi3_wave_control_leading;

static const value_string cigi3_wave_control_scope_vals[] = {
    {0, "Global"},
    {1, "Regional"},
    {2, "Entity"},
    {0, NULL},
};

static const value_string cigi3_wave_control_breaker_type_vals[] = {
    {0, "Plunging"},
    {1, "Spilling"},
    {2, "Surging"},
    {0, NULL},
};

/* CIGI4 Wave Control */
#define CIGI4_PACKET_SIZE_WAVE_CONTROL 32

/* CIGI3 Terrestrial Surface Conditions Control */
#define CIGI3_PACKET_SIZE_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL 8
static int hf_cigi3_terrestrial_surface_conditions_control;
static int hf_cigi3_terrestrial_surface_conditions_control_entity_region_id;
static int hf_cigi3_terrestrial_surface_conditions_control_surface_condition_id;
static int hf_cigi3_terrestrial_surface_conditions_control_surface_condition_enable;
static int hf_cigi3_terrestrial_surface_conditions_control_scope;
static int hf_cigi3_terrestrial_surface_conditions_control_severity;
static int hf_cigi3_terrestrial_surface_conditions_control_coverage;

static const value_string cigi3_terrestrial_surface_conditions_control_scope_vals[] = {
    {0, "Global"},
    {1, "Regional"},
    {2, "Entity"},
    {0, NULL},
};

/* CIGI4 Terrestrial Surface Conditions Control */
#define CIGI4_PACKET_SIZE_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL 16

/* CIGI3 View Control */
#define CIGI3_PACKET_SIZE_VIEW_CONTROL 32
static int hf_cigi3_view_control;
static int hf_cigi3_view_control_view_id;
static int hf_cigi3_view_control_group_id;
static int hf_cigi3_view_control_xoff_enable;
static int hf_cigi3_view_control_yoff_enable;
static int hf_cigi3_view_control_zoff_enable;
static int hf_cigi3_view_control_roll_enable;
static int hf_cigi3_view_control_pitch_enable;
static int hf_cigi3_view_control_yaw_enable;
static int hf_cigi3_view_control_entity_id;
static int hf_cigi3_view_control_xoff;
static int hf_cigi3_view_control_yoff;
static int hf_cigi3_view_control_zoff;
static int hf_cigi3_view_control_roll;
static int hf_cigi3_view_control_pitch;
static int hf_cigi3_view_control_yaw;

/* CIGI4 View Control */
#define CIGI4_PACKET_SIZE_VIEW_CONTROL 40
static int hf_cigi4_view_control_enable_flags;

static int  ett_cigi4_view_control_enable_flags;

/* CIGI3 Sensor Control */
#define CIGI3_PACKET_SIZE_SENSOR_CONTROL 24
static int hf_cigi3_sensor_control;
static int hf_cigi3_sensor_control_view_id;
static int hf_cigi3_sensor_control_sensor_id;
static int hf_cigi3_sensor_control_sensor_on_off;
static int hf_cigi3_sensor_control_polarity;
static int hf_cigi3_sensor_control_line_dropout_enable;
static int hf_cigi3_sensor_control_auto_gain;
static int hf_cigi3_sensor_control_track_white_black;
static int hf_cigi3_sensor_control_track_mode;
static int hf_cigi3_sensor_control_response_type;
static int hf_cigi3_sensor_control_gain;
static int hf_cigi3_sensor_control_level;
static int hf_cigi3_sensor_control_ac_coupling;
static int hf_cigi3_sensor_control_noise;

static const value_string cigi3_sensor_control_track_mode_vals[] = {
    {0, "Off"},
    {1, "Force Correlate"},
    {2, "Scene"},
    {3, "Target"},
    {4, "Ship"},
    {5, "Defined by IG"},
    {6, "Defined by IG"},
    {7, "Defined by IG"},
    {0, NULL},
};

static const true_false_string cigi3_sensor_control_polarity_tfs = {
    "Black hot",
    "White hot"
};


/* CIGI4 Sensor Control */
#define CIGI4_PACKET_SIZE_SENSOR_CONTROL 32

/* CIGI3 Motion Tracker Control */
#define CIGI3_PACKET_SIZE_MOTION_TRACKER_CONTROL 8
static int hf_cigi3_motion_tracker_control;
static int hf_cigi3_motion_tracker_control_view_group_id;
static int hf_cigi3_motion_tracker_control_tracker_id;
static int hf_cigi3_motion_tracker_control_tracker_enable;
static int hf_cigi3_motion_tracker_control_boresight_enable;
static int hf_cigi3_motion_tracker_control_x_enable;
static int hf_cigi3_motion_tracker_control_y_enable;
static int hf_cigi3_motion_tracker_control_z_enable;
static int hf_cigi3_motion_tracker_control_roll_enable;
static int hf_cigi3_motion_tracker_control_pitch_enable;
static int hf_cigi3_motion_tracker_control_yaw_enable;
static int hf_cigi3_motion_tracker_control_view_group_select;

static const true_false_string cigi3_motion_tracker_control_view_group_select_tfs = {
    "View Group",
    "View"
};

/* CIGI4 Motion Tracker Control */
#define CIGI4_PACKET_SIZE_MOTION_TRACKER_CONTROL 16

/* CIGI3 Earth Reference Model Definition */
#define CIGI3_PACKET_SIZE_EARTH_REFERENCE_MODEL_DEFINITION 24
static int hf_cigi3_earth_reference_model_definition;
static int hf_cigi3_earth_reference_model_definition_erm_enable;
static int hf_cigi3_earth_reference_model_definition_equatorial_radius;
static int hf_cigi3_earth_reference_model_definition_flattening;

/* CIGI4 Earth Reference Model Definition */
#define CIGI4_PACKET_SIZE_EARTH_REFERENCE_MODEL_DEFINITION 24

/* CIGI3 Trajectory Definition */
#define CIGI3_PACKET_SIZE_TRAJECTORY_DEFINITION 24
static int hf_cigi3_trajectory_definition;
static int hf_cigi3_trajectory_definition_entity_id;
static int hf_cigi3_trajectory_definition_acceleration_x;
static int hf_cigi3_trajectory_definition_acceleration_y;
static int hf_cigi3_trajectory_definition_acceleration_z;
static int hf_cigi3_trajectory_definition_retardation_rate;
static int hf_cigi3_trajectory_definition_terminal_velocity;


/* CIGI4 Acceleration Control */
#define CIGI4_PACKET_SIZE_ACCELERATION_CONTROL 32
static int hf_cigi4_acceleration_control;
static int hf_cigi4_acceleration_control_entity_id;
static int hf_cigi4_acceleration_control_articulated_part_id;
static int hf_cigi4_acceleration_control_apply_to_part;
static int hf_cigi4_acceleration_control_coord_system;
static int hf_cigi4_acceleration_control_acceleration_x;
static int hf_cigi4_acceleration_control_acceleration_y;
static int hf_cigi4_acceleration_control_acceleration_z;
static int hf_cigi4_acceleration_control_acceleration_roll;
static int hf_cigi4_acceleration_control_acceleration_pitch;
static int hf_cigi4_acceleration_control_acceleration_yaw;


/* CIGI3 View Definition */
#define CIGI3_PACKET_SIZE_VIEW_DEFINITION 32
static int hf_cigi3_view_definition;
static int hf_cigi3_view_definition_view_id;
static int hf_cigi3_view_definition_group_id;
static int hf_cigi3_view_definition_near_enable;
static int hf_cigi3_view_definition_far_enable;
static int hf_cigi3_view_definition_left_enable;
static int hf_cigi3_view_definition_right_enable;
static int hf_cigi3_view_definition_top_enable;
static int hf_cigi3_view_definition_bottom_enable;
static int hf_cigi3_view_definition_mirror_mode;
static int hf_cigi3_view_definition_pixel_replication;
static int hf_cigi3_view_definition_projection_type;
static int hf_cigi3_view_definition_reorder;
static int hf_cigi3_view_definition_view_type;
static int hf_cigi3_view_definition_near;
static int hf_cigi3_view_definition_far;
static int hf_cigi3_view_definition_left;
static int hf_cigi3_view_definition_right;
static int hf_cigi3_view_definition_top;
static int hf_cigi3_view_definition_bottom;

static const value_string cigi3_view_definition_mirror_mode_vals[] = {
    {0, "None"},
    {1, "Horizontal"},
    {2, "Vertical"},
    {3, "Horizontal and Vertical"},
    {0, NULL},
};

static const value_string cigi3_view_definition_pixel_replication_vals[] = {
    {0, "None"},
    {1, "1x2"},
    {2, "2x1"},
    {3, "2x2"},
    {4, "Defined by IG"},
    {5, "Defined by IG"},
    {6, "Defined by IG"},
    {7, "Defined by IG"},
    {0, NULL},
};

static const true_false_string cigi3_view_definition_projection_type_tfs = {
    "Orthographic Parallel",
    "Perspective"
};

static const true_false_string cigi3_view_definition_reorder_tfs = {
    "Bring to Top",
    "No Reorder"
};

/* CIGI4 View Definition */
#define CIGI4_PACKET_SIZE_VIEW_DEFINITION 40

/* CIGI3 Collision Detection Segment Definition */
#define CIGI3_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_DEFINITION 40
static int hf_cigi3_collision_detection_segment_definition;
static int hf_cigi3_collision_detection_segment_definition_entity_id;
static int hf_cigi3_collision_detection_segment_definition_segment_id;
static int hf_cigi3_collision_detection_segment_definition_segment_enable;
static int hf_cigi3_collision_detection_segment_definition_x1;
static int hf_cigi3_collision_detection_segment_definition_y1;
static int hf_cigi3_collision_detection_segment_definition_z1;
static int hf_cigi3_collision_detection_segment_definition_x2;
static int hf_cigi3_collision_detection_segment_definition_y2;
static int hf_cigi3_collision_detection_segment_definition_z2;
static int hf_cigi3_collision_detection_segment_definition_material_mask;


/* CIGI4 Collision Detection Segment Definition */
#define CIGI4_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_DEFINITION 40

/* CIGI3 Collision Detection Volume Definition */
#define CIGI3_PACKET_SIZE_COLLISION_DETECTION_VOLUME_DEFINITION 48
static int hf_cigi3_collision_detection_volume_definition;
static int hf_cigi3_collision_detection_volume_definition_entity_id;
static int hf_cigi3_collision_detection_volume_definition_volume_id;
static int hf_cigi3_collision_detection_volume_definition_volume_enable;
static int hf_cigi3_collision_detection_volume_definition_volume_type;
static int hf_cigi3_collision_detection_volume_definition_x;
static int hf_cigi3_collision_detection_volume_definition_y;
static int hf_cigi3_collision_detection_volume_definition_z;
static int hf_cigi3_collision_detection_volume_definition_radius_height;
static int hf_cigi3_collision_detection_volume_definition_width;
static int hf_cigi3_collision_detection_volume_definition_depth;
static int hf_cigi3_collision_detection_volume_definition_roll;
static int hf_cigi3_collision_detection_volume_definition_pitch;
static int hf_cigi3_collision_detection_volume_definition_yaw;

static const true_false_string cigi3_collision_detection_volume_definition_volume_type_tfs = {
    "Cuboid",
    "Sphere"
};

/* CIGI4 Collision Detection Volume Definition */
#define CIGI4_PACKET_SIZE_COLLISION_DETECTION_VOLUME_DEFINITION 48

/* CIGI3 HAT/HOT Request */
#define CIGI3_PACKET_SIZE_HAT_HOT_REQUEST 32
static int hf_cigi3_hat_hot_request;
static int hf_cigi3_hat_hot_request_hat_hot_id;
static int hf_cigi3_hat_hot_request_type;
static int hf_cigi3_hat_hot_request_coordinate_system;
static int hf_cigi3_2_hat_hot_request_update_period;
static int hf_cigi3_hat_hot_request_entity_id;
static int hf_cigi3_hat_hot_request_lat_xoff;
static int hf_cigi3_hat_hot_request_lon_yoff;
static int hf_cigi3_hat_hot_request_alt_zoff;

static const value_string cigi3_hat_hot_request_type_vals[] = {
    {0, "HAT"},
    {1, "HOT"},
    {2, "Extended"},
    {0, NULL},
};

/* CIGI4 HAT/HOT Request */
#define CIGI4_PACKET_SIZE_HAT_HOT_REQUEST    40
static int hf_cigi4_hat_hot_request_flags;

static int ett_cigi4_hat_hot_request_flags;

/* CIGI3 Line of Sight Segment Request */
#define CIGI3_PACKET_SIZE_LINE_OF_SIGHT_SEGMENT_REQUEST 64
static int hf_cigi3_line_of_sight_segment_request;
static int hf_cigi3_line_of_sight_segment_request_los_id;
static int hf_cigi3_line_of_sight_segment_request_type;
static int hf_cigi3_line_of_sight_segment_request_source_coord;
static int hf_cigi3_line_of_sight_segment_request_destination_coord;
static int hf_cigi3_line_of_sight_segment_request_response_coord;
static int hf_cigi3_line_of_sight_segment_request_alpha_threshold;
static int hf_cigi3_line_of_sight_segment_request_source_entity_id;
static int hf_cigi3_line_of_sight_segment_request_source_lat_xoff;
static int hf_cigi3_line_of_sight_segment_request_source_lon_yoff;
static int hf_cigi3_line_of_sight_segment_request_source_alt_zoff;
static int hf_cigi3_line_of_sight_segment_request_destination_lat_xoff;
static int hf_cigi3_line_of_sight_segment_request_destination_lon_yoff;
static int hf_cigi3_line_of_sight_segment_request_destination_alt_zoff;
static int hf_cigi3_line_of_sight_segment_request_material_mask;

/* CIGI3_2 Line of Sight Segment Request */
static int hf_cigi3_2_line_of_sight_segment_request_destination_entity_id_valid;
static int hf_cigi3_2_line_of_sight_segment_request_update_period;
static int hf_cigi3_2_line_of_sight_segment_request_destination_entity_id;

/* CIGI4 Line of Sight Segment Request */
#define CIGI4_PACKET_SIZE_LINE_OF_SIGHT_SEGMENT_REQUEST 72

/* CIGI3 Line of Sight Vector Request */
#define CIGI3_PACKET_SIZE_LINE_OF_SIGHT_VECTOR_REQUEST 56
static int hf_cigi3_line_of_sight_vector_request;
static int hf_cigi3_line_of_sight_vector_request_los_id;
static int hf_cigi3_line_of_sight_vector_request_type;
static int hf_cigi3_line_of_sight_vector_request_source_coord;
static int hf_cigi3_line_of_sight_vector_request_response_coord;
static int hf_cigi3_line_of_sight_vector_request_alpha;
static int hf_cigi3_line_of_sight_vector_request_entity_id;
static int hf_cigi3_line_of_sight_vector_request_azimuth;
static int hf_cigi3_line_of_sight_vector_request_elevation;
static int hf_cigi3_line_of_sight_vector_request_min_range;
static int hf_cigi3_line_of_sight_vector_request_max_range;
static int hf_cigi3_line_of_sight_vector_request_source_lat_xoff;
static int hf_cigi3_line_of_sight_vector_request_source_lon_yoff;
static int hf_cigi3_line_of_sight_vector_request_source_alt_zoff;
static int hf_cigi3_line_of_sight_vector_request_material_mask;

/* CIGI3_2 Line of Sight Vector Request */
static int hf_cigi3_2_line_of_sight_vector_request_update_period;

/* CIGI4 Line of Sight Vector Request */
#define CIGI4_PACKET_SIZE_LINE_OF_SIGHT_VECTOR_REQUEST 64

/* CIGI3 Position Request */
#define CIGI3_PACKET_SIZE_POSITION_REQUEST 8
static int hf_cigi3_position_request;
static int hf_cigi3_position_request_object_id;
static int hf_cigi3_position_request_part_id;
static int hf_cigi3_position_request_update_mode;
static int hf_cigi3_position_request_object_class;
static int hf_cigi3_position_request_coord_system;

static const true_false_string cigi3_position_request_update_mode_tfs = {
    "Continuous",
    "One-Shot"
};

static const value_string cigi3_position_request_object_class_vals[] = {
    {0, "Entity"},
    {1, "Articulated Part"},
    {2, "View"},
    {3, "View Group"},
    {4, "Motion Tracker"},
    {0, NULL},
};

static const value_string cigi3_position_request_coord_system_vals[] = {
    {0, "Geodetic"},
    {1, "Parent Entity"},
    {2, "Submodel"},
    {0, NULL},
};

/* CIGI4 Position Request */
#define CIGI4_PACKET_SIZE_POSITION_REQUEST 8

/* CIGI3 Environmental Conditions Request */
#define CIGI3_PACKET_SIZE_ENVIRONMENTAL_CONDITIONS_REQUEST 32
static int hf_cigi3_environmental_conditions_request;
static int hf_cigi3_environmental_conditions_request_type;
static int hf_cigi3_environmental_conditions_request_id;
static int hf_cigi3_environmental_conditions_request_lat;
static int hf_cigi3_environmental_conditions_request_lon;
static int hf_cigi3_environmental_conditions_request_alt;

static const value_string cigi3_environmental_conditions_request_type_vals[] = {
    {1, "Maritime Surface Conditions"},
    {2, "Terrestrial Surface Conditions"},
    {3, "Maritime+Terrestrial Surface Conditions"},
    {4, "Weather Conditions"},
    {5, "Maritime+Weather Surface Conditions"},
    {6, "Terrestrial+Weather Surface Conditions"},
    {7, "Maritime+Terrestrial+Weather Surface Conditions"},
    {8, "Aerosol Concentrations"},
    {9, "Maritime Surface Conditions+Aerosol Concentrations"},
    {10, "Terrestrial Surface Conditions+Aerosol Concentrations"},
    {11, "Maritime+Terrestrial Surface Conditions+Aerosol Concentrations"},
    {12, "Weather Conditions+Aerosol Concentrations"},
    {13, "Maritime+Weather Surface Conditions+Aerosol Concentrations"},
    {14, "Terrestrial+Weather Surface Conditions+Aerosol Concentrations"},
    {15, "Maritime+Terrestrial+Weather Surface Conditions+Aerosol Concentrations"},
    {0, NULL},
};

/* CIGI4 Environmental Conditions Request */
#define CIGI4_PACKET_SIZE_ENVIRONMENTAL_CONDITIONS_REQUEST 32

/* CIGI3_3 Symbol Surface Definition */
#define CIGI3_PACKET_SIZE_SYMBOL_SURFACE_DEFINITION 56
static int hf_cigi3_3_symbol_surface_definition;
static int hf_cigi3_3_symbol_surface_definition_surface_id;
static int hf_cigi3_3_symbol_surface_definition_surface_state;
static int hf_cigi3_3_symbol_surface_definition_attach_type;
static int hf_cigi3_3_symbol_surface_definition_billboard;
static int hf_cigi3_3_symbol_surface_definition_perspective_growth_enable;
static int hf_cigi3_3_symbol_surface_definition_entity_view_id;
static int hf_cigi3_3_symbol_surface_definition_xoff_left;
static int hf_cigi3_3_symbol_surface_definition_yoff_right;
static int hf_cigi3_3_symbol_surface_definition_zoff_top;
static int hf_cigi3_3_symbol_surface_definition_yaw_bottom;
static int hf_cigi3_3_symbol_surface_definition_pitch;
static int hf_cigi3_3_symbol_surface_definition_roll;
static int hf_cigi3_3_symbol_surface_definition_width;
static int hf_cigi3_3_symbol_surface_definition_height;
static int hf_cigi3_3_symbol_surface_definition_min_u;
static int hf_cigi3_3_symbol_surface_definition_max_u;
static int hf_cigi3_3_symbol_surface_definition_min_v;
static int hf_cigi3_3_symbol_surface_definition_max_v;

static const true_false_string cigi3_3_symbol_surface_definition_surface_state_tfs = {
    "Destroyed",
    "Active"
};

static const true_false_string cigi3_3_symbol_surface_definition_attach_type_tfs = {
    "View",
    "Entity"
};

static const true_false_string cigi3_3_symbol_surface_definition_billboard_tfs = {
    "Billboard",
    "Non-Billboard"
};


/* CIGI4 Symbol Surface Definition */
#define CIGI4_PACKET_SIZE_SYMBOL_SURFACE_DEFINITION 64

/* CIGI3_3 Symbol Text Definition */
// Variable Length
static int hf_cigi3_3_symbol_text_definition;
static int hf_cigi3_3_symbol_text_definition_symbol_id;
static int hf_cigi3_3_symbol_text_definition_orientation;
static int hf_cigi3_3_symbol_text_definition_alignment;
static int hf_cigi3_3_symbol_text_definition_font_ident;
static int hf_cigi3_3_symbol_text_definition_font_size;
static int hf_cigi3_3_symbol_text_definition_text;

static const value_string cigi3_3_symbol_text_definition_alignment_vals[] = {
    {0, "Top Left"},
    {1, "Top Center"},
    {2, "Top Right"},
    {3, "Center Left"},
    {4, "Center"},
    {5, "Center Right"},
    {6, "Bottom Left"},
    {7, "Bottom Center"},
    {8, "Bottom Right"},
    {0, NULL}
};

static const value_string cigi3_3_symbol_text_definition_orientation_vals[] = {
    {0, "Left To Right"},
    {1, "Top To Bottom"},
    {2, "Right To Left"},
    {3, "Bottom To Top"},
    {0, NULL}
};

static const value_string cigi3_3_symbol_text_definition_font_ident_vals[] = {
    {0, "IG Default"},
    {1, "Proportional Sans Serif"},
    {2, "Proportional Sans Serif Bold"},
    {3, "Proportional Sans Serif Italic"},
    {4, "Proportional Sans Serif Bold Italic"},
    {5, "Proportional Serif"},
    {6, "Proportional Serif Bold"},
    {7, "Proportional Serif Italic"},
    {8, "Proportional Serif Bold Italic"},
    {9, "Monospace Sans Serif"},
    {10, "Monospace Sans Serif Bold"},
    {11, "Monospace Sans Serif Italic"},
    {12, "Monospace Sans Serif Bold Italic"},
    {13, "Monospace Serif"},
    {14, "Monospace Serif Bold"},
    {15, "Monospace Serif Italic"},
    {16, "Monospace Serif Bold Italic"},
    {0, NULL}
};

/* CIGI4 Symbol Text Definition */
//#define CIGI4_PACKET_SIZE_SYMBOL_TEXT_DEFINITION                    (12 + text_length)

/* CIGI3_3 Symbol Circle Definition */
// Variable length
static int hf_cigi3_3_symbol_circle_definition;
static int hf_cigi3_3_symbol_circle_definition_symbol_id;
static int hf_cigi3_3_symbol_circle_definition_drawing_style;
static int hf_cigi3_3_symbol_circle_definition_stipple_pattern;
static int hf_cigi3_3_symbol_circle_definition_line_width;
static int hf_cigi3_3_symbol_circle_definition_stipple_pattern_length;
static int hf_cigi3_3_symbol_circle_definition_center_u[9];
static int hf_cigi3_3_symbol_circle_definition_center_v[9];
static int hf_cigi3_3_symbol_circle_definition_radius[9];
static int hf_cigi3_3_symbol_circle_definition_inner_radius[9];
static int hf_cigi3_3_symbol_circle_definition_start_angle[9];
static int hf_cigi3_3_symbol_circle_definition_end_angle[9];

static const true_false_string cigi3_3_symbol_circle_definition_drawing_style_tfs = {
    "Fill",
    "Line"
};

/* CIGI4 Symbol Circle Definition */
//#define CIGI4_PACKET_SIZE_SYMBOL_CIRCLE_DEFINITION (24 + (8*n))
static int hf_cigi4_symbol_circle_definition_circles;

static int ett_cigi4_symbol_circle_definition_circles;

/* CIGI3_3 Symbol Line Definition */
// Variable length
static int hf_cigi3_3_symbol_line_definition;
static int hf_cigi3_3_symbol_line_definition_symbol_id;
static int hf_cigi3_3_symbol_line_definition_primitive_type;
static int hf_cigi3_3_symbol_line_definition_stipple_pattern;
static int hf_cigi3_3_symbol_line_definition_line_width;
static int hf_cigi3_3_symbol_line_definition_stipple_pattern_length;
static int hf_cigi3_3_symbol_line_definition_vertex_u[29];
static int hf_cigi3_3_symbol_line_definition_vertex_v[29];

static const value_string cigi3_3_symbol_line_definition_primitive_type_vals[] = {
    {0, "Point"},
    {1, "Line"},
    {2, "Line Strip"},
    {3, "Line Loop"},
    {4, "Triangle"},
    {5, "Triangle Strip"},
    {6, "Triangle Fan"},
    {0, NULL}
};

/* CIGI4 Symbol Polygon Definition */
/* Symbol Line Definition packet renamed. */
//#define CIGI4_PACKET_SIZE_SYMBOL_POLYGON_DEFINITION                 24 + (8 x n)
static int hf_cigi4_symbol_polygon_definition;
static int hf_cigi4_symbol_polygon_definition_symbol_id;
static int hf_cigi4_symbol_polygon_definition_primitive_type;
static int hf_cigi4_symbol_polygon_definition_stipple_pattern;
static int hf_cigi4_symbol_polygon_definition_line_width;
static int hf_cigi4_symbol_polygon_definition_stipple_pattern_length;
static int hf_cigi4_symbol_polygon_definition_vertex_u[29];
static int hf_cigi4_symbol_polygon_definition_vertex_v[29];
static int hf_cigi4_symbol_polygon_definition_vertices;

static int ett_cigi4_symbol_polygon_definition_vertices;

/* CIGI3_3 Symbol Clone */
#define CIGI3_PACKET_SIZE_SYMBOL_CLONE 8
static int hf_cigi3_3_symbol_clone;
static int hf_cigi3_3_symbol_clone_symbol_id;
static int hf_cigi3_3_symbol_clone_source_type;
static int hf_cigi3_3_symbol_clone_source_id;

static const true_false_string cigi3_3_symbol_clone_source_type_tfs = {
    "Symbol Template",
    "Symbol"
};

/* CIG4 Symbol Clone */
#define CIGI4_PACKET_SIZE_SYMBOL_CLONE 16

/* CIGI3_3 Symbol Control */
#define CIGI3_PACKET_SIZE_SYMBOL_CONTROL 40
static int hf_cigi3_3_symbol_control;
static int hf_cigi3_3_symbol_control_symbol_id;
static int hf_cigi3_3_symbol_control_symbol_state;
static int hf_cigi3_3_symbol_control_attach_state;
static int hf_cigi3_3_symbol_control_flash_control;
static int hf_cigi3_3_symbol_control_inherit_color;
static int hf_cigi3_3_symbol_control_parent_symbol_ident;
static int hf_cigi3_3_symbol_control_surface_ident;
static int hf_cigi3_3_symbol_control_layer;
static int hf_cigi3_3_symbol_control_flash_duty_cycle;
static int hf_cigi3_3_symbol_control_flash_period;
static int hf_cigi3_3_symbol_control_position_u;
static int hf_cigi3_3_symbol_control_position_v;
static int hf_cigi3_3_symbol_control_rotation;
static int hf_cigi3_3_symbol_control_red;
static int hf_cigi3_3_symbol_control_green;
static int hf_cigi3_3_symbol_control_blue;
static int hf_cigi3_3_symbol_control_alpha;
static int hf_cigi3_3_symbol_control_scale_u;
static int hf_cigi3_3_symbol_control_scale_v;

static const value_string cigi3_3_symbol_control_symbol_state_vals[] = {
    {0, "Hidden"},
    {1, "Visible"},
    {2, "Destroyed"},
    {0, NULL}
};

static const true_false_string cigi3_3_symbol_control_flash_control_tfs = {
    "Reset",
    "Continue"
};


/* CIGI4 Symbol Control */
#define CIGI4_PACKET_SIZE_SYMBOL_CONTROL 48

/* CIGI3_3 Short Symbol Control */
#define CIGI3_PACKET_SIZE_SHORT_SYMBOL_CONTROL 32
static int hf_cigi3_3_short_symbol_control;
static int hf_cigi3_3_short_symbol_control_symbol_id;
static int hf_cigi3_3_short_symbol_control_inherit_color;
static int hf_cigi3_3_short_symbol_control_flash_control;
static int hf_cigi3_3_short_symbol_control_attach_state;
static int hf_cigi3_3_short_symbol_control_symbol_state;
static int hf_cigi3_3_short_symbol_control_attribute_select1;
static int hf_cigi3_3_short_symbol_control_attribute_select2;
static int hf_cigi3_3_short_symbol_control_attribute_value1;
static int hf_cigi3_3_short_symbol_control_attribute_value2;
static int hf_cigi3_3_short_symbol_control_attribute_value1f;
static int hf_cigi3_3_short_symbol_control_attribute_value2f;
static int hf_cigi3_3_short_symbol_control_red1;
static int hf_cigi3_3_short_symbol_control_green1;
static int hf_cigi3_3_short_symbol_control_blue1;
static int hf_cigi3_3_short_symbol_control_alpha1;
static int hf_cigi3_3_short_symbol_control_red2;
static int hf_cigi3_3_short_symbol_control_green2;
static int hf_cigi3_3_short_symbol_control_blue2;
static int hf_cigi3_3_short_symbol_control_alpha2;

static const value_string cigi3_3_short_symbol_control_attribute_select_vals[] = {
    {0, "None"},
    {1, "Surface ID"},
    {2, "Parent Symbol ID"},
    {3, "Layer"},
    {4, "Flash Duty Cycle Percentage"},
    {5, "Flash Period"},
    {6, "Position U"},
    {7, "Position V"},
    {8, "Rotation"},
    {9, "Color"},
    {10,"Scale U"},
    {11,"Scale V"},
    {0, NULL}
};


/* CIGI4 Short Symbol Control */
#define CIGI4_PACKET_SIZE_SHORT_SYMBOL_CONTROL 24

/* CIGI4 Symbol Textured Circle */
//#define CIGI4_PACKET_SIZE_SYMBOL_CIRCLE_TEXTURED_DEFINITION         16 + (40 x n)
static int hf_cigi4_symbol_circle_textured_definition;
static int hf_cigi4_symbol_circle_textured_definition_symbol_id;
static int hf_cigi4_symbol_circle_textured_definition_texture_id;
static int hf_cigi4_symbol_circle_textured_definition_filter_mode;
static int hf_cigi4_symbol_circle_textured_definition_wrap;
static int hf_cigi4_symbol_circle_textured_definition_center_u[9];
static int hf_cigi4_symbol_circle_textured_definition_center_v[9];
static int hf_cigi4_symbol_circle_textured_definition_radius[9];
static int hf_cigi4_symbol_circle_textured_definition_inner_radius[9];
static int hf_cigi4_symbol_circle_textured_definition_start_angle[9];
static int hf_cigi4_symbol_circle_textured_definition_end_angle[9];
static int hf_cigi4_symbol_circle_textured_definition_texture_center_u[9];
static int hf_cigi4_symbol_circle_textured_definition_texture_center_v[9];
static int hf_cigi4_symbol_circle_textured_definition_texture_radius[9];
static int hf_cigi4_symbol_circle_textured_definition_texture_rotation[9];
static int hf_cigi4_symbol_circle_textured_definition_circles;

static int ett_cigi4_symbol_circle_textured_definition_circles;

/* CIGI4 Symbol Textured Polygon */
//#define CIGI4_PACKET_SIZE_SYMBOL_POLYGON_TEXTURED_DEFINITION        16 + (16 x n)
static int hf_cigi4_symbol_polygon_textured_definition;
static int hf_cigi4_symbol_polygon_textured_definition_symbol_id;
static int hf_cigi4_symbol_polygon_textured_definition_texture_id;
static int hf_cigi4_symbol_polygon_textured_definition_filter_mode;
static int hf_cigi4_symbol_polygon_textured_definition_wrap;
static int hf_cigi4_symbol_polygon_textured_definition_vertices;
static int hf_cigi4_symbol_polygon_textured_definition_vertex_u[29];
static int hf_cigi4_symbol_polygon_textured_definition_vertex_v[29];
static int hf_cigi4_symbol_polygon_textured_definition_texture_center_u[29];
static int hf_cigi4_symbol_polygon_textured_definition_texture_center_v[29];

static int ett_cigi4_symbol_polygon_textured_definition_vertices;

/* CIGI3 Start of Frame */
#define CIGI3_PACKET_SIZE_START_OF_FRAME 16
static int hf_cigi3_start_of_frame;
static int hf_cigi3_start_of_frame_db_number;
static int hf_cigi3_start_of_frame_ig_status;
static int hf_cigi3_start_of_frame_ig_mode;
static int hf_cigi3_start_of_frame_timestamp_valid;
static int hf_cigi3_start_of_frame_earth_reference_model;
static int hf_cigi3_start_of_frame_frame_ctr;
static int hf_cigi3_start_of_frame_timestamp;

static const value_string cigi3_start_of_frame_ig_mode_vals[] = {
    {0, "Reset/Standby"},
    {1, "Operate"},
    {2, "Debug"},
    {3, "Offline Maintenance"},
    {0, NULL},
};

static const true_false_string cigi3_start_of_frame_earth_reference_model_tfs = {
    "Host-Defined",
    "WGS 84"
};

/* CIGI3_2 Start of Frame */
#define CIGI3_2_PACKET_SIZE_START_OF_FRAME 24
static int hf_cigi3_2_start_of_frame;
static int hf_cigi3_2_start_of_frame_minor_version;
static int hf_cigi3_2_start_of_frame_ig_frame_number;
static int hf_cigi3_2_start_of_frame_last_host_frame_number;

/* CIGI3 HAT/HOT Response */
#define CIGI3_PACKET_SIZE_HAT_HOT_RESPONSE 16
static int hf_cigi3_hat_hot_response;
static int hf_cigi3_hat_hot_response_hat_hot_id;
static int hf_cigi3_hat_hot_response_valid;
static int hf_cigi3_hat_hot_response_type;
static int hf_cigi3_hat_hot_response_height;

static const true_false_string cigi3_hat_hot_response_type_tfs = {
    "HOT",
    "HAT"
};

/* CIGI3_2 HAT/HOT Response */
static int hf_cigi3_2_hat_hot_response_host_frame_number_lsn;

/* CIGI4 HAT/HOT Response */
#define CIGI4_PACKET_SIZE_HAT_HOT_RESPONSE 16
static int hf_cigi4_hat_hot_response_flags;

static int ett_cigi4_hat_hot_response_flags;

/* CIGI3 HAT/HOT Extended Response */
#define CIGI3_PACKET_SIZE_HAT_HOT_EXTENDED_RESPONSE 40
static int hf_cigi3_hat_hot_extended_response;
static int hf_cigi3_hat_hot_extended_response_hat_hot_id;
static int hf_cigi3_hat_hot_extended_response_valid;
static int hf_cigi3_hat_hot_extended_response_hat;
static int hf_cigi3_hat_hot_extended_response_hot;
static int hf_cigi3_hat_hot_extended_response_material_code;
static int hf_cigi3_hat_hot_extended_response_normal_vector_azimuth;
static int hf_cigi3_hat_hot_extended_response_normal_vector_elevation;

/* CIGI3_2 HAT/HOT Extended Response */
static int hf_cigi3_2_hat_hot_extended_response_host_frame_number_lsn;

/* CIGI4 HAT/HOT Extended Response */
#define CIGI4_PACKET_SIZE_HAT_HOT_EXTENDED_RESPONSE 40
static int hf_cigi4_hat_hot_extended_response_flags;

static int ett_cigi4_hat_hot_extended_response_flags;

/* CIGI3 Line of Sight Response */
#define CIGI3_PACKET_SIZE_LINE_OF_SIGHT_RESPONSE 16
static int hf_cigi3_line_of_sight_response;
static int hf_cigi3_line_of_sight_response_los_id;
static int hf_cigi3_line_of_sight_response_valid;
static int hf_cigi3_line_of_sight_response_entity_id_valid;
static int hf_cigi3_line_of_sight_response_visible;
static int hf_cigi3_line_of_sight_response_count;
static int hf_cigi3_line_of_sight_response_entity_id;
static int hf_cigi3_line_of_sight_response_range;

/* CIGI3_2 Line of Sight Response */
static int hf_cigi3_2_line_of_sight_response_host_frame_number_lsn;

/* CIGI4 Line of Sight Response */
#define CIGI4_PACKET_SIZE_LINE_OF_SIGHT_RESPONSE 24

/* CIGI3 Line of Sight Extended Response */
#define CIGI3_PACKET_SIZE_LINE_OF_SIGHT_EXTENDED_RESPONSE 56
static int hf_cigi3_line_of_sight_extended_response;
static int hf_cigi3_line_of_sight_extended_response_los_id;
static int hf_cigi3_line_of_sight_extended_response_valid;
static int hf_cigi3_line_of_sight_extended_response_entity_id_valid;
static int hf_cigi3_line_of_sight_extended_response_range_valid;
static int hf_cigi3_line_of_sight_extended_response_visible;
static int hf_cigi3_line_of_sight_extended_response_intersection_coord;
static int hf_cigi3_line_of_sight_extended_response_response_count;
static int hf_cigi3_line_of_sight_extended_response_entity_id;
static int hf_cigi3_line_of_sight_extended_response_range;
static int hf_cigi3_line_of_sight_extended_response_lat_xoff;
static int hf_cigi3_line_of_sight_extended_response_lon_yoff;
static int hf_cigi3_line_of_sight_extended_response_alt_zoff;
static int hf_cigi3_line_of_sight_extended_response_red;
static int hf_cigi3_line_of_sight_extended_response_green;
static int hf_cigi3_line_of_sight_extended_response_blue;
static int hf_cigi3_line_of_sight_extended_response_alpha;
static int hf_cigi3_line_of_sight_extended_response_material_code;
static int hf_cigi3_line_of_sight_extended_response_normal_vector_azimuth;
static int hf_cigi3_line_of_sight_extended_response_normal_vector_elevation;

/* CIGI3_2 Line of Sight Extended Response */
static int hf_cigi3_2_line_of_sight_extended_response_host_frame_number_lsn;

/* CIGI4 Line of Sight Extended Response */
#define CIGI4_PACKET_SIZE_LINE_OF_SIGHT_EXTENDED_RESPONSE 64

/* CIGI3 Sensor Response */
#define CIGI3_PACKET_SIZE_SENSOR_RESPONSE 24
static int hf_cigi3_sensor_response;
static int hf_cigi3_sensor_response_view_id;
static int hf_cigi3_sensor_response_sensor_id;
static int hf_cigi3_sensor_response_sensor_status;
static int hf_cigi3_sensor_response_gate_x_size;
static int hf_cigi3_sensor_response_gate_y_size;
static int hf_cigi3_sensor_response_gate_x_pos;
static int hf_cigi3_sensor_response_gate_y_pos;
static int hf_cigi3_sensor_response_frame_ctr;

static const value_string cigi3_sensor_response_sensor_status_vals[] = {
    {0, "Searching for target"},
    {1, "Tracking target"},
    {2, "Impending breaklock"},
    {3, "Breaklock"},
    {0, NULL},
};

/* CIGI4 Sensor Response */
#define CIGI4_PACKET_SIZE_SENSOR_RESPONSE 24

/* CIGI3 Sensor Extended Response */
#define CIGI3_PACKET_SIZE_SENSOR_EXTENDED_RESPONSE 48
static int hf_cigi3_sensor_extended_response;
static int hf_cigi3_sensor_extended_response_view_id;
static int hf_cigi3_sensor_extended_response_sensor_id;
static int hf_cigi3_sensor_extended_response_sensor_status;
static int hf_cigi3_sensor_extended_response_entity_id_valid;
static int hf_cigi3_sensor_extended_response_entity_id;
static int hf_cigi3_sensor_extended_response_gate_x_size;
static int hf_cigi3_sensor_extended_response_gate_y_size;
static int hf_cigi3_sensor_extended_response_gate_x_pos;
static int hf_cigi3_sensor_extended_response_gate_y_pos;
static int hf_cigi3_sensor_extended_response_frame_ctr;
static int hf_cigi3_sensor_extended_response_track_lat;
static int hf_cigi3_sensor_extended_response_track_lon;
static int hf_cigi3_sensor_extended_response_track_alt;

static const value_string cigi3_sensor_extended_response_sensor_status_vals[] = {
    {0, "Searching for target"},
    {1, "Tracking target"},
    {2, "Impending breaklock"},
    {3, "Breaklock"},
    {0, NULL},
};


/* CIGI4 Sensor Extended Response */
#define CIGI4_PACKET_SIZE_SENSOR_EXTENDED_RESPONSE 56

/* CIGI3 Position Response */
#define CIGI3_PACKET_SIZE_POSITION_RESPONSE 48
static int hf_cigi3_position_response;
static int hf_cigi3_position_response_object_id;
static int hf_cigi3_position_response_part_id;
static int hf_cigi3_position_response_object_class;
static int hf_cigi3_position_response_coord_system;
static int hf_cigi3_position_response_lat_xoff;
static int hf_cigi3_position_response_lon_yoff;
static int hf_cigi3_position_response_alt_zoff;
static int hf_cigi3_position_response_roll;
static int hf_cigi3_position_response_pitch;
static int hf_cigi3_position_response_yaw;

static const value_string cigi3_position_response_object_class_vals[] = {
    {0, "Entity"},
    {1, "Articulated Part"},
    {2, "View"},
    {3, "View Group"},
    {4, "Motion Tracker"},
    {0, NULL},
};

static const value_string cigi3_position_response_coord_system_vals[] = {
    {0, "Geodetic"},
    {1, "Parent Entity"},
    {2, "Submodel"},
    {0, NULL},
};


/* CIGI4 Position Response */
#define CIGI4_PACKET_SIZE_POSITION_RESPONSE 48

/* CIGI3 Weather Conditions Response */
#define CIGI3_PACKET_SIZE_WEATHER_CONDITIONS_RESPONSE 32
static int hf_cigi3_weather_conditions_response;
static int hf_cigi3_weather_conditions_response_request_id;
static int hf_cigi3_weather_conditions_response_humidity;
static int hf_cigi3_weather_conditions_response_air_temp;
static int hf_cigi3_weather_conditions_response_visibility_range;
static int hf_cigi3_weather_conditions_response_horiz_speed;
static int hf_cigi3_weather_conditions_response_vert_speed;
static int hf_cigi3_weather_conditions_response_wind_direction;
static int hf_cigi3_weather_conditions_response_barometric_pressure;

/* CIGI4 Weather Conditions Response */
#define CIGI4_PACKET_SIZE_WEATHER_CONDITIONS_RESPONSE 32

/* CIGI3 Aerosol Concentration Response */
#define CIGI3_PACKET_SIZE_AEROSOL_CONCENTRATION_RESPONSE 8
static int hf_cigi3_aerosol_concentration_response;
static int hf_cigi3_aerosol_concentration_response_request_id;
static int hf_cigi3_aerosol_concentration_response_layer_id;
static int hf_cigi3_aerosol_concentration_response_aerosol_concentration;

/* CIGI4 Aerosol Concentration Response */
#define CIGI4_PACKET_SIZE_AEROSOL_CONCENTRATION_RESPONSE 16

/* CIGI3 Maritime Surface Conditions Response */
#define CIGI3_PACKET_SIZE_MARITIME_SURFACE_CONDITIONS_RESPONSE 16
static int hf_cigi3_maritime_surface_conditions_response;
static int hf_cigi3_maritime_surface_conditions_response_request_id;
static int hf_cigi3_maritime_surface_conditions_response_sea_surface_height;
static int hf_cigi3_maritime_surface_conditions_response_surface_water_temp;
static int hf_cigi3_maritime_surface_conditions_response_surface_clarity;

/* CIGI4 Maritime Surface Conditions Response */
#define CIGI4_PACKET_SIZE_MARITIME_SURFACE_CONDITIONS_RESPONSE 24

/* CIGI3 Terrestrial Surface Conditions Response */
#define CIGI3_PACKET_SIZE_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE 8
static int hf_cigi3_terrestrial_surface_conditions_response;
static int hf_cigi3_terrestrial_surface_conditions_response_request_id;
static int hf_cigi3_terrestrial_surface_conditions_response_surface_id;

/* CIGI4 Terrestrial Surface Conditions Response */
#define CIGI4_PACKET_SIZE_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE 16

/* CIGI3 Collision Detection Segment Notification */
#define CIGI3_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_NOTIFICATION 16
static int hf_cigi3_collision_detection_segment_notification;
static int hf_cigi3_collision_detection_segment_notification_entity_id;
static int hf_cigi3_collision_detection_segment_notification_segment_id;
static int hf_cigi3_collision_detection_segment_notification_type;
static int hf_cigi3_collision_detection_segment_notification_contacted_entity_id;
static int hf_cigi3_collision_detection_segment_notification_material_code;
static int hf_cigi3_collision_detection_segment_notification_intersection_distance;

static const true_false_string cigi3_collision_detection_segment_notification_type_tfs = {
    "Entity",
    "Non-entity"
};

/* CIGI4 Collision Detection Segment Notification */
#define CIGI4_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_NOTIFICATION 24

/* CIGI3 Collision Detection Volume Notification */
#define CIGI3_PACKET_SIZE_COLLISION_DETECTION_VOLUME_NOTIFICATION 16
static int hf_cigi3_collision_detection_volume_notification;
static int hf_cigi3_collision_detection_volume_notification_entity_id;
static int hf_cigi3_collision_detection_volume_notification_volume_id;
static int hf_cigi3_collision_detection_volume_notification_type;
static int hf_cigi3_collision_detection_volume_notification_contacted_entity_id;
static int hf_cigi3_collision_detection_volume_notification_contacted_volume_id;

static const true_false_string cigi3_collision_detection_volume_notification_type_tfs = {
    "Entity",
    "Non-entity"
};

/* CIGI4 Collision Detection Volume Notification */
#define CIGI4_PACKET_SIZE_COLLISION_DETECTION_VOLUME_NOTIFICATION 16

/* CIGI3 Animation Stop Notification */
#define CIGI3_PACKET_SIZE_ANIMATION_STOP_NOTIFICATION 8
static int hf_cigi3_animation_stop_notification;
static int hf_cigi3_animation_stop_notification_entity_id;

/* CIGI4 Animation Stop Notification */
#define CIGI4_PACKET_SIZE_ANIMATION_STOP_NOTIFICATION 8

/* CIGI3 Event Notification */
#define CIGI3_PACKET_SIZE_EVENT_NOTIFICATION 16
static int hf_cigi3_event_notification;
static int hf_cigi3_event_notification_event_id;
static int hf_cigi3_event_notification_data_1;
static int hf_cigi3_event_notification_data_2;
static int hf_cigi3_event_notification_data_3;

/* CIGI4 Event Notification */
#define CIGI4_PACKET_SIZE_EVENT_NOTIFICATION 24

/* CIGI3 Image Generator Message */
static int hf_cigi3_image_generator_message;
static int hf_cigi3_image_generator_message_id;
static int hf_cigi3_image_generator_message_message;

/* CIGI4 Image Generator Message */

/* CIGI3 User-Defined Packets */
static int hf_cigi3_user_defined;

/* CIGI4 Locally Defined Packets */
static int hf_cigi4_locally_defined;

/* CIGI4 Registered Packets */
static int hf_cigi4_registered;

static expert_field ei_cigi_invalid_len;


/* CIGI4 Packet ID */
static int hf_cigi4_packet_id;
static int hf_cigi4_packet_size;
#define CIGI4_PACKET_ID_IG_CONTROL                                   0x00
#define CIGI4_PACKET_ID_ENTITY_POSITION                              0x01
#define CIGI4_PACKET_ID_CONFORMAL_CLAMPED_ENTITY_POSITION            0x02
#define CIGI4_PACKET_ID_COMPONENT_CONTROL                            0x03
#define CIGI4_PACKET_ID_SHORT_COMPONENT_CONTROL                      0x04
#define CIGI4_PACKET_ID_ARTICULATED_PART_CONTROL                     0x05
#define CIGI4_PACKET_ID_SHORT_ARTICULATED_PART_CONTROL               0x06
#define CIGI4_PACKET_ID_VELOCITY_CONTROL                             0x07
#define CIGI4_PACKET_ID_CELESTIAL_SPHERE_CONTROL                     0x08
#define CIGI4_PACKET_ID_ATMOSPHERE_CONTROL                           0x09
#define CIGI4_PACKET_ID_ENVIRONMENTAL_REGION_CONTROL                 0x0A
#define CIGI4_PACKET_ID_WEATHER_CONTROL                              0x0B
#define CIGI4_PACKET_ID_MARITIME_SURFACE_CONDITIONS_CONTROL          0x0C
#define CIGI4_PACKET_ID_WAVE_CONTROL                                 0x0D
#define CIGI4_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL       0x0E
#define CIGI4_PACKET_ID_VIEW_CONTROL                                 0x0F
#define CIGI4_PACKET_ID_SENSOR_CONTROL                               0x10
#define CIGI4_PACKET_ID_MOTION_TRACKER_CONTROL                       0x11
#define CIGI4_PACKET_ID_EARTH_REFERENCE_MODEL_DEFINITION             0x12
#define CIGI4_PACKET_ID_ACCELERATION_CONTROL                         0x13
#define CIGI4_PACKET_ID_VIEW_DEFINITION                              0x14
#define CIGI4_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION       0x15
#define CIGI4_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION        0x16
#define CIGI4_PACKET_ID_HAT_HOT_REQUEST                              0x17
#define CIGI4_PACKET_ID_LINE_OF_SIGHT_SEGMENT_REQUEST                0x18
#define CIGI4_PACKET_ID_LINE_OF_SIGHT_VECTOR_REQUEST                 0x19
#define CIGI4_PACKET_ID_POSITION_REQUEST                             0x1A
#define CIGI4_PACKET_ID_ENVIRONMENTAL_CONDITIONS_REQUEST             0x1B
#define CIGI4_PACKET_ID_SYMBOL_SURFACE_DEFINITION                    0x1C
#define CIGI4_PACKET_ID_SYMBOL_TEXT_DEFINITION                       0x1D
#define CIGI4_PACKET_ID_SYMBOL_CIRCLE_DEFINITION                     0x1E
#define CIGI4_PACKET_ID_SYMBOL_POLYGON_DEFINITION                    0x1F
#define CIGI4_PACKET_ID_SYMBOL_CLONE                                 0x20
#define CIGI4_PACKET_ID_SYMBOL_CONTROL                               0x21
#define CIGI4_PACKET_ID_SHORT_SYMBOL_CONTROL                         0x22
#define CIGI4_PACKET_ID_SYMBOL_CIRCLE_TEXTURED_DEFINITION            0x23
#define CIGI4_PACKET_ID_SYMBOL_POLYGON_TEXTURED_DEFINITION           0x24
#define CIGI4_PACKET_ID_ENTITY_CONTROL                               0x25
#define CIGI4_PACKET_ID_ANIMATION_CONTROL                            0x26

#define CIGI4_PACKET_ID_IMAGE_GENERATOR_MESSAGE                    0x0FF0
#define CIGI4_PACKET_ID_EVENT_NOTIFICATION                         0x0FF1
#define CIGI4_PACKET_ID_ANIMATION_STOP_NOTIFICATION                0x0FF2
#define CIGI4_PACKET_ID_COLLISION_DETECTION_VOLUME_NOTIFICATION    0x0FF3
#define CIGI4_PACKET_ID_COLLISION_DETECTION_SEGMENT_NOTIFICATION   0x0FF4
#define CIGI4_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE    0x0FF5
#define CIGI4_PACKET_ID_MARITIME_SURFACE_CONDITIONS_RESPONSE       0x0FF6
#define CIGI4_PACKET_ID_AEROSOL_CONCENTRATION_RESPONSE             0x0FF7
#define CIGI4_PACKET_ID_WEATHER_CONDITIONS_RESPONSE                0x0FF8
#define CIGI4_PACKET_ID_POSITION_RESPONSE                          0x0FF9
#define CIGI4_PACKET_ID_SENSOR_EXTENDED_RESPONSE                   0x0FFA
#define CIGI4_PACKET_ID_SENSOR_RESPONSE                            0x0FFB
#define CIGI4_PACKET_ID_LINE_OF_SIGHT_EXTENDED_RESPONSE            0x0FFC
#define CIGI4_PACKET_ID_LINE_OF_SIGHT_RESPONSE                     0x0FFD
#define CIGI4_PACKET_ID_HAT_HOT_EXTENDED_RESPONSE                  0x0FFE
#define CIGI4_PACKET_ID_HAT_HOT_RESPONSE                           0x0FFF
#define CIGI4_PACKET_ID_START_OF_FRAME                             0xFFFF

/* These locally defined values mean that perhaps a range_string
 * is more appropriate than a value_string.
 */
#define CIGI4_PACKET_ID_LOCALLY_DEFINED_MAX                        0xFFFE
#define CIGI4_PACKET_ID_LOCALLY_DEFINED_MIN                        0x8000
#define CIGI4_PACKET_ID_REGISTERED_MAX                             0x7FFF
#define CIGI4_PACKET_ID_REGISTERED_MIN                             0x1000

static const value_string cigi4_packet_id_vals[] = {
    {CIGI4_PACKET_ID_IG_CONTROL, "IG Control"},
    {CIGI4_PACKET_ID_ENTITY_POSITION, "Entity Position"},
    {CIGI4_PACKET_ID_CONFORMAL_CLAMPED_ENTITY_POSITION, "Conformal Clamped Entity Position"},
    {CIGI4_PACKET_ID_COMPONENT_CONTROL, "Component Control"},
    {CIGI4_PACKET_ID_SHORT_COMPONENT_CONTROL, "Short Component Control"},
    {CIGI4_PACKET_ID_ARTICULATED_PART_CONTROL, "Articulated Part Control"},
    {CIGI4_PACKET_ID_SHORT_ARTICULATED_PART_CONTROL, "Short Articulated Part Control"},
    {CIGI4_PACKET_ID_VELOCITY_CONTROL, "Velocity Control"},
    {CIGI4_PACKET_ID_CELESTIAL_SPHERE_CONTROL, "Celestial Sphere Control"},
    {CIGI4_PACKET_ID_ATMOSPHERE_CONTROL, "Atmosphere Control"},
    {CIGI4_PACKET_ID_ENVIRONMENTAL_REGION_CONTROL, "Environmental Region Control"},
    {CIGI4_PACKET_ID_WEATHER_CONTROL, "Weather Control"},
    {CIGI4_PACKET_ID_MARITIME_SURFACE_CONDITIONS_CONTROL, "Maritime Surface Conditions Control"},
    {CIGI4_PACKET_ID_WAVE_CONTROL, "Wave Control"},
    {CIGI4_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL, "Terrestrial Surface Conditions Control"},
    {CIGI4_PACKET_ID_VIEW_CONTROL, "View Control"},
    {CIGI4_PACKET_ID_SENSOR_CONTROL, "Sensor Control"},
    {CIGI4_PACKET_ID_MOTION_TRACKER_CONTROL, "Motion Tracker Control"},
    {CIGI4_PACKET_ID_EARTH_REFERENCE_MODEL_DEFINITION, "Earth Reference Model Definition"},
    {CIGI4_PACKET_ID_ACCELERATION_CONTROL, "Acceleration Definition"},
    {CIGI4_PACKET_ID_VIEW_DEFINITION, "View Definition"},
    {CIGI4_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION, "Collision Detection Segment Definition"},
    {CIGI4_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION, "Collision Detection Volume Definition"},
    {CIGI4_PACKET_ID_HAT_HOT_REQUEST, "HAT/HOT Request"},
    {CIGI4_PACKET_ID_LINE_OF_SIGHT_SEGMENT_REQUEST, "Line of Sight Segment Request"},
    {CIGI4_PACKET_ID_LINE_OF_SIGHT_VECTOR_REQUEST, "Line of Sight Vector Request"},
    {CIGI4_PACKET_ID_POSITION_REQUEST, "Position Request"},
    {CIGI4_PACKET_ID_ENVIRONMENTAL_CONDITIONS_REQUEST, "Environmental Conditions Request"},
    {CIGI4_PACKET_ID_SYMBOL_SURFACE_DEFINITION, "Symbol Surface Definition"},
    {CIGI4_PACKET_ID_SYMBOL_TEXT_DEFINITION, "Symbol Text Definition"},
    {CIGI4_PACKET_ID_SYMBOL_CIRCLE_DEFINITION, "Symbol Circle Definition"},
    {CIGI4_PACKET_ID_SYMBOL_POLYGON_DEFINITION, "Symbol Polygon Definition"},
    {CIGI4_PACKET_ID_SYMBOL_CLONE, "Symbol Clone"},
    {CIGI4_PACKET_ID_SYMBOL_CONTROL, "Symbol Control"},
    {CIGI4_PACKET_ID_SHORT_SYMBOL_CONTROL, "Short Symbol Control"},
    {CIGI4_PACKET_ID_SYMBOL_CIRCLE_TEXTURED_DEFINITION, "Symbol Textured Circle Definition"},
    {CIGI4_PACKET_ID_SYMBOL_POLYGON_TEXTURED_DEFINITION, "Symbol Textured Polygon Definition"},
    {CIGI4_PACKET_ID_ENTITY_CONTROL, "Entity Control"},
    {CIGI4_PACKET_ID_ANIMATION_CONTROL, "Animation Control"},

    {CIGI4_PACKET_ID_IMAGE_GENERATOR_MESSAGE, "Image Generator Message"},
    {CIGI4_PACKET_ID_EVENT_NOTIFICATION, "Event Notification"},
    {CIGI4_PACKET_ID_ANIMATION_STOP_NOTIFICATION, "Animation Stop Notification"},
    {CIGI4_PACKET_ID_COLLISION_DETECTION_VOLUME_NOTIFICATION, "Collision Detection Volume Notification"},
    {CIGI4_PACKET_ID_COLLISION_DETECTION_SEGMENT_NOTIFICATION, "Collision Detection Segment Notification"},
    {CIGI4_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE, "Terrestrial Surface Conditions Response"},
    {CIGI4_PACKET_ID_MARITIME_SURFACE_CONDITIONS_RESPONSE, "Maritime Surface Conditions Response"},
    {CIGI4_PACKET_ID_AEROSOL_CONCENTRATION_RESPONSE, "Aerosol Concentration Response"},
    {CIGI4_PACKET_ID_WEATHER_CONDITIONS_RESPONSE, "Weather Conditions Response"},
    {CIGI4_PACKET_ID_POSITION_RESPONSE, "Position Response"},
    {CIGI4_PACKET_ID_SENSOR_EXTENDED_RESPONSE, "Sensor Extended Response"},
    {CIGI4_PACKET_ID_SENSOR_RESPONSE, "Sensor Response"},
    {CIGI4_PACKET_ID_LINE_OF_SIGHT_EXTENDED_RESPONSE, "Line of Sight Extended Response"},
    {CIGI4_PACKET_ID_LINE_OF_SIGHT_RESPONSE, "Line of Sight Response"},
    {CIGI4_PACKET_ID_HAT_HOT_EXTENDED_RESPONSE, "HAT/HOT Extended Response"},
    {CIGI4_PACKET_ID_HAT_HOT_RESPONSE, "HAT/HOT Response"},
    {CIGI4_PACKET_ID_START_OF_FRAME, "Start of Frame"},
    {0, NULL}
};
static value_string_ext cigi4_packet_id_vals_ext = VALUE_STRING_EXT_INIT(cigi4_packet_id_vals);


/* CIGI4 IG Control */
#define CIGI4_PACKET_SIZE_IG_CONTROL 24
static int hf_cigi4_ig_control_flags;
static int hf_cigi4_ig_control_smoothing_enable;
static int hf_cigi4_ig_control_entity_substitution;
static int hf_cigi4_ig_control_entity_substitution_enable;

static int ett_cigi4_ig_control_flags;
static int ett_cigi4_ig_control_entity_substitution;

/* CIGI4 Entity Position */
/* Subset of previous (CIGI3) Entity Control packet containing parameters
 * for entity position and attitude. */
#define CIGI4_PACKET_SIZE_ENTITY_POSITION 48
static int hf_cigi4_entity_position;
static int hf_cigi4_entity_position_entity_id;
static int hf_cigi4_entity_position_flags;
static int hf_cigi4_entity_position_attach_state;
static int hf_cigi4_entity_position_ground_ocean_clamp;
static int hf_cigi4_entity_position_parent_id;
static int hf_cigi4_entity_position_roll;
static int hf_cigi4_entity_position_pitch;
static int hf_cigi4_entity_position_yaw;
static int hf_cigi4_entity_position_lat_xoff;
static int hf_cigi4_entity_position_lon_yoff;
static int hf_cigi4_entity_position_alt_zoff;

static int ett_cigi4_entity_position_flags;

/* CIGI Conformal Clamped Entity Position */
/* Conformal Clamped Entity Control packet renamed. */
#define CIGI4_PACKET_SIZE_CONFORMAL_CLAMPED_ENTITY_POSITION         32
static int hf_cigi4_conformal_clamped_entity_position;
static int hf_cigi4_conformal_clamped_entity_position_entity_id;
static int hf_cigi4_conformal_clamped_entity_position_yaw;
static int hf_cigi4_conformal_clamped_entity_position_lat;
static int hf_cigi4_conformal_clamped_entity_position_lon;

#define CIGI4_PACKET_SIZE_COMPONENT_CONTROL                         40

#define CIGI4_PACKET_SIZE_SHORT_COMPONENT_CONTROL                   24

static const value_string cigi4_entity_control_ground_ocean_clamp_vals[] = {
    {0, "No Clamp"},
    {1, "Non-Conformal"},
    {2, "Conformal"},
    {0, NULL},
};

/* CIGI4 Start of Frame*/
#define CIGI4_PACKET_SIZE_START_OF_FRAME 24
static int hf_cigi4_start_of_frame;
static int hf_cigi4_start_of_frame_db_number;
static int hf_cigi4_start_of_frame_ig_status;
static int hf_cigi4_start_of_frame_flags;
static int hf_cigi4_start_of_frame_ig_mode;
static int hf_cigi4_start_of_frame_timestamp_valid;
static int hf_cigi4_start_of_frame_earth_reference_model;
static int hf_cigi4_start_of_frame_minor_version;
static int hf_cigi4_start_of_frame_ig_frame_number;
static int hf_cigi4_start_of_frame_timestamp;
static int hf_cigi4_start_of_frame_ig_condition_flags;
static int hf_cigi4_start_of_frame_last_host_frame_number;
static int hf_cigi4_start_of_frame_condition_overframing;
static int hf_cigi4_start_of_frame_condition_paging;
static int hf_cigi4_start_of_frame_condition_excessive_variable_length_data;

static int ett_cigi4_start_of_frame_flags;
static int ett_cigi4_start_of_frame_ig_condition_flags;


/*
static const true_false_string cigi4_entity_control_animation_direction_tfs = {
    "Backward",
    "Forward"
};

static const true_false_string cigi4_entity_control_animation_loop_mode_tfs = {
    "Continuous",
    "One-Shot"
};

static const value_string cigi4_entity_control_animation_state_vals[] = {
    {0, "Stop"},
    {1, "Pause"},
    {2, "Play"},
    {3, "Continue"},
    {0, NULL},
};*/



/* Global preferences */
#define CIGI_VERSION_FROM_PACKET 0
#define CIGI_VERSION_1   1
#define CIGI_VERSION_2   2
#define CIGI_VERSION_3   3
#define CIGI_VERSION_4   4

#define CIGI_VERSION_4_IGC 0
#define CIGI_VERSION_4_SOF 0xFF
/* CIIG Standard Version 4, 4.5 Message Structure: "The special Packet IDs
 * assigned to the IG Control and Start of Frame packets permit a multi-version
 * CIGI parser to differentiate between the old and new message structure as
 * both 0h and FFh are unknown CIGI major version numbers."
 */

static int global_cigi_version = CIGI_VERSION_FROM_PACKET;

#define CIGI_BYTE_ORDER_FROM_PACKET   -1
#define CIGI_BYTE_ORDER_BIG_ENDIAN    0
#define CIGI_BYTE_ORDER_LITTLE_ENDIAN 1

static int global_cigi_byte_order = CIGI_BYTE_ORDER_FROM_PACKET;

static const char *global_host_ip;
static const char *global_ig_ip;


/* Initialize the subtree pointers */
static int ett_cigi;

/* The version of cigi to use */
static int cigi_version;
static int cigi_minor_version;

/* The byte order of cigi to use; our default is big-endian */
static int cigi_byte_order = ENC_BIG_ENDIAN;

/*
 * Extract a 16-bit fixed-point value and convert it to a float.
 */
static float
cigi_get_fixed_point(tvbuff_t *tvb, int offset, const unsigned encoding)
{
    int16_t fixed = tvb_get_uint16(tvb, offset, encoding);
    return fixed / 128.0F;
}

/*
 * Check whether this looks like a CIGI packet or not.
 */
static bool
packet_is_cigi(tvbuff_t *tvb)
{
    uint16_t packet_id;
    uint16_t packet_size;
    uint8_t cigi_version_local;
    uint8_t ig_mode;

    /* CIGI 3 */
    uint16_t byte_swap;

    if (tvb_captured_length(tvb) < 3) {
        /* Not enough data available to check */
        return false;
    }

    packet_id = tvb_get_uint8(tvb, 0);
    packet_size = tvb_get_uint8(tvb, 1);
    cigi_version_local = tvb_get_uint8(tvb, 2);
    switch ( cigi_version_local ) {

        case CIGI_VERSION_1:
            /* CIGI 1 requires that the first packet is always the IG Control or SOF */
            switch ( packet_id ) {
                case 1:
                    if ( packet_size != 16 ) {
                        return false;
                    }

                    if (!tvb_bytes_exist(tvb, 4, 1)) {
                        /* Not enough data available to check */
                        return false;
                    }
                    ig_mode = (tvb_get_uint8(tvb, 4) & 0xc0) >> 6;
                    if ( ig_mode > 2 ) {
                        return false;
                    }
                    break;
                case 101:
                    if ( packet_size != 12 ) {
                        return false;
                    }
                    break;
                default:
                    return false;
            }
            break;

        case CIGI_VERSION_2:
            /* CIGI 2 requires that the first packet is always the IG Control or SOF */
            switch ( packet_id ) {
                case CIGI2_PACKET_ID_IG_CONTROL:
                    if ( packet_size != CIGI2_PACKET_SIZE_IG_CONTROL ) {
                        return false;
                    }

                    if (!tvb_bytes_exist(tvb, 4, 1)) {
                        /* Not enough data available to check */
                        return false;
                    }
                    ig_mode = (tvb_get_uint8(tvb, 4) & 0xc0) >> 6;
                    if ( ig_mode > 2 ) {
                        return false;
                    }
                    break;
                case CIGI2_PACKET_ID_START_OF_FRAME:
                    if ( packet_size != CIGI2_PACKET_SIZE_START_OF_FRAME ) {
                        return false;
                    }
                    break;
                default:
                    return false;
            }
            break;

        case CIGI_VERSION_3:
            if (!tvb_bytes_exist(tvb, 6, 1)) {
                /* Not enough data available to check byte swap field */
                return false;
            }

            /* CIGI 3 requires that the first packet is always the IG Control or SOF */
            switch ( packet_id ) {
                case CIGI3_PACKET_ID_IG_CONTROL:
                    if ( packet_size != CIGI3_PACKET_SIZE_IG_CONTROL ) {
                        if ( packet_size != CIGI3_2_PACKET_SIZE_IG_CONTROL ) {
                            return false;
                        }
                    }

                    if (!tvb_bytes_exist(tvb, 4, 2)) {
                        /* Not enough data available to check */
                        return false;
                    }

                    ig_mode = (tvb_get_uint8(tvb, 4) & 0x03);
                    if ( ig_mode > 2 ) {
                        return false;
                    }

                    break;
                case CIGI3_PACKET_ID_START_OF_FRAME:
                    if ( packet_size != CIGI3_PACKET_SIZE_START_OF_FRAME ) {
                        if ( packet_size != CIGI3_2_PACKET_SIZE_START_OF_FRAME) {
                            return false;
                        }
                    }

                    if (!tvb_bytes_exist(tvb, 5, 1)) {
                        /* Not enough data available to check */
                        return false;
                    }

                    break;
                default:
                    return false;
            }

            /* CIGI 3 has the byte swap field which only allows two values. */
            byte_swap = tvb_get_ntohs(tvb, 6);

            if ( byte_swap != CIGI3_BYTE_SWAP_BIG_ENDIAN && byte_swap != CIGI3_BYTE_SWAP_LITTLE_ENDIAN ) {
                return false;
            }
            break;

        case CIGI_VERSION_4_IGC:
        case CIGI_VERSION_4_SOF:
            /* CIGI 4 introduces a 4 byte header, with 16-bit packet size
             * and packet ID (yes, they're in the opposite order of the
             * previous versions; now packet size comes first). The version
             * number is now located in the fifth byte. Since the first packet
             * is required to be the IG Control or SOF, the third byte must be
             * 0x00 or 0xFF, regardless of endianness.
             */
            if (!tvb_bytes_exist(tvb, 4, 1)) {
                /* Not enough data available to check */
                return false;
            }
            //test if it's CIGI version 4
            if (tvb_get_uint8(tvb, 4) != CIGI_VERSION_4)
                return false;

            /* CIGI 4 requires that the first packet is always the IG Control or SOF */

            //PacketSize If the parser detects a zero in the "leftmost" byte, then the message is in Big Endian byte
            if (packet_id == 0) {
                /* Big Endian */
                packet_size = tvb_get_uint16(tvb, 0, ENC_BIG_ENDIAN);
                packet_id = tvb_get_uint16(tvb, 2, ENC_BIG_ENDIAN);
            } else if (packet_size == 0) {
                /* Little Endian */
                packet_size = tvb_get_uint16(tvb, 0, ENC_LITTLE_ENDIAN);
                packet_id = tvb_get_uint16(tvb, 2, ENC_LITTLE_ENDIAN);
            } else {
                return false;
            }

            switch (packet_id) {
            case CIGI4_PACKET_ID_IG_CONTROL:
                if (packet_size != CIGI4_PACKET_SIZE_IG_CONTROL) {
                    return false;
                }

                if (!tvb_bytes_exist(tvb, 7, 2)) {
                    /* Not enough data available to check */
                    return false;
                }

                ig_mode = (tvb_get_uint8(tvb, 7) & 0x03);
                if (ig_mode > 2) {
                    return false;
                }
                break;

            case CIGI4_PACKET_ID_START_OF_FRAME:
                if (packet_size != CIGI4_PACKET_SIZE_START_OF_FRAME) {
                    return false;
                }
                break;
            default:
                return false;
            }
            break;
        default:
            return false;
    }

    /* Check that the frame contains at least the first PDU's worth
     * of data. (We can't check this until we know the CIGI version
     * because CIGI version 4 stores the packet size differently.)
     */
    if ( packet_size > tvb_reported_length(tvb) ) {
        return false;
    }

    /* If we made it here, then this is probably CIGI */
    return true;
}

/*
 * The heuristic dissector
 */
static bool
dissect_cigi_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Does this look like CIGI? */
    if ( !packet_is_cigi(tvb) ) {
        return false;
    }
    dissect_cigi_pdu(tvb, pinfo, tree);
    return true;
}

/*
 * The non-heuristic dissector.
 */
static int
dissect_cigi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Make sure this looks like CIGI */
    if ( !packet_is_cigi(tvb) ) {
        return 0;
    }
    dissect_cigi_pdu(tvb, pinfo, tree);
    /* We probably ate the entire packet. */
    return tvb_reported_length(tvb);
}

/* Code to actually dissect the CIGI packets */
static void
dissect_cigi_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    uint16_t packet_id = 0;

    proto_item *ti, *hidden_item;
    proto_tree *cigi_tree;

    const char* src_str;
    const char* dest_str;


    if ((tvb_get_ntohs(tvb, 0) & 0xFF00) == 0) {
        packet_id = tvb_get_uint16(tvb, 2, ENC_BIG_ENDIAN);     //packet_id is not at the same location
    }
    else {
        packet_id = tvb_get_uint16(tvb, 2, ENC_LITTLE_ENDIAN);
    }

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIGI");

    /* If we have the start of frame or IG Control packet set the version
     * XXX - If another version of cigi is added to this dissector be sure to
     * place the IG Control and SOF packet id's in this comparison. */
    if ( ( packet_id == CIGI2_PACKET_ID_IG_CONTROL || packet_id == CIGI2_PACKET_ID_START_OF_FRAME || packet_id == CIGI3_PACKET_ID_IG_CONTROL || packet_id == CIGI3_PACKET_ID_START_OF_FRAME ) && global_cigi_version == CIGI_VERSION_FROM_PACKET ) {
        cigi_version = tvb_get_uint8(tvb, 2);
    }
    else if ((packet_id == CIGI4_PACKET_ID_IG_CONTROL || packet_id == CIGI4_PACKET_ID_START_OF_FRAME) && global_cigi_version == CIGI_VERSION_FROM_PACKET) {
        cigi_version = tvb_get_uint8(tvb, 4);
    }

    /* Format the Info String */
    src_str = address_to_str(pinfo->pool, &pinfo->src);
    if ( !g_ascii_strcasecmp(global_host_ip, src_str) ) {
        src_str = "Host";
    } else if ( !g_ascii_strcasecmp(global_ig_ip, src_str) ) {
        src_str = "IG";
    }

    dest_str = address_to_str(pinfo->pool, &pinfo->dst);
    if ( !g_ascii_strcasecmp(global_host_ip, dest_str) ) {
        dest_str = "Host";
    } else if ( !g_ascii_strcasecmp(global_ig_ip, dest_str) ) {
        dest_str = "IG";
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s => %s (%u bytes)", src_str, dest_str,
        tvb_reported_length(tvb));

    if (tree) {

        ti = proto_tree_add_protocol_format(tree, proto_cigi, tvb, 0, tvb_reported_length(tvb), "Common Image Generator Interface (%i), %s => %s (%u bytes)",
                                            cigi_version, src_str, dest_str, tvb_reported_length(tvb));

        cigi_tree = proto_item_add_subtree(ti, ett_cigi);

        /* Ports */
        hidden_item = proto_tree_add_uint(cigi_tree, hf_cigi_src_port, tvb, 0, 0, pinfo->srcport);
        proto_item_set_hidden(hidden_item);
        hidden_item = proto_tree_add_uint(cigi_tree, hf_cigi_dest_port, tvb, 0, 0, pinfo->destport);
        proto_item_set_hidden(hidden_item);
        hidden_item = proto_tree_add_uint(cigi_tree, hf_cigi_port, tvb, 0, 0, pinfo->srcport);
        proto_item_set_hidden(hidden_item);
        hidden_item = proto_tree_add_uint(cigi_tree, hf_cigi_port, tvb, 0, 0, pinfo->destport);
        proto_item_set_hidden(hidden_item);

        /* Frame Size */
        hidden_item = proto_tree_add_uint(cigi_tree, hf_cigi_frame_size, tvb, 0, 0, tvb_reported_length(tvb));
        proto_item_set_hidden(hidden_item);

        /* Since the versions of CIGI are not backwards compatible,
         * dissection is different for each version.
         * XXX - If another version of cigi is added to this dissector be
         * sure to place the version in this statement.*/
        if ( cigi_version == CIGI_VERSION_2 ) {
            cigi2_add_tree(tvb, pinfo, cigi_tree);
        } else if ( cigi_version == CIGI_VERSION_3 ) {
            cigi3_add_tree(tvb, pinfo, cigi_tree);
        } else if ( cigi_version == CIGI_VERSION_4 ) {
            cigi4_add_tree(tvb, pinfo, cigi_tree);
        } else {
            /* Since there exists no dissector to dissect this version
             * just put the data into a tree using an unknown version */
            cigi_add_tree(tvb, cigi_tree);
        }
    }
}

/* Create the tree for CIGI (Unknown Version)
 * Note: If we have no version then we assume network order bytes (big endian). */
static void
cigi_add_tree(tvbuff_t *tvb, proto_tree *cigi_tree)
{
    int offset = 0;
    int length = 0;
    int packet_id = 0;
    int packet_size = 0;
    int data_size = 0;

    proto_tree* cigi_packet_tree = NULL;
    proto_item* tipacket;

    length = tvb_reported_length(tvb);

    /* Each iteration through this loop is meant to be a separate cigi packet
     * therefore it is okay to assume that at the top of this look we are given
     * a new packet to dissect. */
    while ( offset < length ) {

        packet_id = tvb_get_uint8(tvb, offset);
        packet_size = tvb_get_uint8(tvb, offset + 1);
        data_size = packet_size;

        /* a cigi packet must be at least 2 bytes long
           ( 1 - packet_id; 2 - packet_size ) */
        if ( packet_size < 2 )
            return;

        /* If we have the start of frame or IG Control packet set the version.
         * Since we have no cigi version we assume that packet id 1 is the
         * IG Control and packet id 101 is the Start of Frame. */
        if ( ( packet_id == 1 || packet_id == 101 ) && global_cigi_version == CIGI_VERSION_FROM_PACKET ) {
            cigi_version = tvb_get_uint8(tvb, 2);
        }

        /* Add the subtree for the packet */
        tipacket = proto_tree_add_none_format(cigi_tree, hf_cigi_unknown, tvb, offset, packet_size, "Unknown (%i bytes)", packet_size);

        cigi_packet_tree = proto_item_add_subtree(tipacket, ett_cigi);

        /* In all CIGI versions the first byte of a packet is the packet ID.
         * The second byte is the size of the packet (in bytes). */
        proto_tree_add_item(cigi_packet_tree, hf_cigi_packet_id, tvb, offset, 1, cigi_byte_order);
        offset++;
        data_size--;

        proto_tree_add_item(cigi_packet_tree, hf_cigi_packet_size, tvb, offset, 1, cigi_byte_order);
        offset++;
        data_size--;

        /* If the packet ID is for the SOF or IG Control, which are usually 101
         * and 1 respectively then also print the version that we are using. */
        if ( packet_id == 1 || packet_id == 101 ) {
            proto_tree_add_item(cigi_packet_tree, hf_cigi_version, tvb, offset, 1, cigi_byte_order);
            offset++;
            data_size--;
        }

        proto_tree_add_item(cigi_packet_tree, hf_cigi_data, tvb, offset, data_size, ENC_NA);
        offset += data_size;
    }
}

/* CIGI Add Data */
/* offset is the position past the packet_id and packet_size.
 * tvb should be trimmed to the appropriate size with e.g.
 * tvb_new_subset_length(). */
static int
cigi_add_data(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    /* Note: CIGI 4 uses a 4 byte packet header (2 byte packet ID
     * and 2 byte packet size), so we cannot inspect previous bytes in
     * order to use this as a common function. */
    int packet_size = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(tree, hf_cigi_data, tvb, offset, packet_size, ENC_NA);
    offset += packet_size;

    return offset;
}

/* Create the tree for CIGI 2
 * Note: CIGI 2 guarantee's that the byte order will be big endian. */
static void
cigi2_add_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cigi_tree)
{
    int offset = 0;
    int length = 0;
    int init_offset = 0;

    int packet_id = 0;
    int packet_size = 0;
    int packet_length = 0;

    proto_tree* cigi_packet_tree = NULL;
    proto_item* tipacket, *ti;
    tvbuff_t* next_tvb;
    int hf_cigi2_packet;

    length = tvb_reported_length(tvb);

    /* Each iteration through this loop is meant to be a separate cigi packet
     * therefore it is okay to assume that at the top of this look we are given
     * a new packet to dissect. */
    while ( offset < length ) {

        packet_id = tvb_get_uint8(tvb, offset);
        packet_size = tvb_get_uint8(tvb, offset + 1);

        /* If we have the start of frame or IG Control packet set the version */
        if ( ( packet_id == CIGI2_PACKET_ID_IG_CONTROL || packet_id == CIGI2_PACKET_ID_START_OF_FRAME ) && global_cigi_version == CIGI_VERSION_FROM_PACKET ) {
            cigi_version = tvb_get_uint8(tvb, 2);
        }

        /* Add the subtree for the packet */
        if ( packet_id == CIGI2_PACKET_ID_IG_CONTROL ) {
            hf_cigi2_packet = hf_cigi2_ig_control;
            packet_length = CIGI2_PACKET_SIZE_IG_CONTROL;
        } else if ( packet_id == CIGI2_PACKET_ID_ENTITY_CONTROL ) {
            hf_cigi2_packet = hf_cigi2_entity_control;
            packet_length = CIGI2_PACKET_SIZE_ENTITY_CONTROL;
        } else if ( packet_id == CIGI2_PACKET_ID_COMPONENT_CONTROL ) {
            hf_cigi2_packet = hf_cigi2_component_control;
            packet_length = CIGI2_PACKET_SIZE_COMPONENT_CONTROL;
        } else if ( packet_id == CIGI2_PACKET_ID_ARTICULATED_PARTS_CONTROL ) {
            hf_cigi2_packet = hf_cigi2_articulated_parts_control;
            packet_length = CIGI2_PACKET_SIZE_ARTICULATED_PARTS_CONTROL;
        } else if ( packet_id == CIGI2_PACKET_ID_RATE_CONTROL ) {
            hf_cigi2_packet = hf_cigi2_rate_control;
            packet_length = CIGI2_PACKET_SIZE_RATE_CONTROL;
        } else if ( packet_id == CIGI2_PACKET_ID_ENVIRONMENT_CONTROL ) {
            hf_cigi2_packet = hf_cigi2_environment_control;
            packet_length = CIGI2_PACKET_SIZE_ENVIRONMENT_CONTROL;
        } else if ( packet_id == CIGI2_PACKET_ID_WEATHER_CONTROL ) {
            hf_cigi2_packet = hf_cigi2_weather_control;
            packet_length = CIGI2_PACKET_SIZE_WEATHER_CONTROL;
        } else if ( packet_id == CIGI2_PACKET_ID_VIEW_CONTROL ) {
            hf_cigi2_packet = hf_cigi2_view_control;
            packet_length = CIGI2_PACKET_SIZE_VIEW_CONTROL;
        } else if ( packet_id == CIGI2_PACKET_ID_SENSOR_CONTROL ) {
            hf_cigi2_packet = hf_cigi2_sensor_control;
            packet_length = CIGI2_PACKET_SIZE_SENSOR_CONTROL;
        } else if ( packet_id == CIGI2_PACKET_ID_TRAJECTORY_DEFINITION ) {
            hf_cigi2_packet = hf_cigi2_trajectory_definition;
            packet_length = CIGI2_PACKET_SIZE_TRAJECTORY_DEFINITION;
        } else if ( packet_id == CIGI2_PACKET_ID_SPECIAL_EFFECT_DEFINITION ) {
            hf_cigi2_packet = hf_cigi2_special_effect_definition;
            packet_length = CIGI2_PACKET_SIZE_SPECIAL_EFFECT_DEFINITION;
        } else if ( packet_id == CIGI2_PACKET_ID_VIEW_DEFINITION ) {
            hf_cigi2_packet = hf_cigi2_view_definition;
            packet_length = CIGI2_PACKET_SIZE_VIEW_DEFINITION;
        } else if ( packet_id == CIGI2_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION ) {
            hf_cigi2_packet = hf_cigi2_collision_detection_segment_definition;
            packet_length = CIGI2_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_DEFINITION;
        } else if ( packet_id == CIGI2_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION ) {
            hf_cigi2_packet = hf_cigi2_collision_detection_volume_definition;
            packet_length = CIGI2_PACKET_SIZE_COLLISION_DETECTION_VOLUME_DEFINITION;
        } else if ( packet_id == CIGI2_PACKET_ID_HEIGHT_ABOVE_TERRAIN_REQUEST ) {
            hf_cigi2_packet = hf_cigi2_height_above_terrain_request;
            packet_length = CIGI2_PACKET_SIZE_HEIGHT_ABOVE_TERRAIN_REQUEST;
        } else if ( packet_id == CIGI2_PACKET_ID_LINE_OF_SIGHT_OCCULT_REQUEST ) {
            hf_cigi2_packet = hf_cigi2_line_of_sight_occult_request;
            packet_length = CIGI2_PACKET_SIZE_LINE_OF_SIGHT_OCCULT_REQUEST;
        } else if ( packet_id == CIGI2_PACKET_ID_LINE_OF_SIGHT_RANGE_REQUEST ) {
            hf_cigi2_packet = hf_cigi2_line_of_sight_range_request;
            packet_length = CIGI2_PACKET_SIZE_LINE_OF_SIGHT_RANGE_REQUEST;
        } else if ( packet_id == CIGI2_PACKET_ID_HEIGHT_OF_TERRAIN_REQUEST ) {
            hf_cigi2_packet = hf_cigi2_height_of_terrain_request;
            packet_length = CIGI2_PACKET_SIZE_HEIGHT_OF_TERRAIN_REQUEST;
        } else if ( packet_id == CIGI2_PACKET_ID_START_OF_FRAME ) {
            hf_cigi2_packet = hf_cigi2_start_of_frame;
            packet_length = CIGI2_PACKET_SIZE_START_OF_FRAME;
        } else if ( packet_id == CIGI2_PACKET_ID_HEIGHT_ABOVE_TERRAIN_RESPONSE ) {
            hf_cigi2_packet = hf_cigi2_height_above_terrain_response;
            packet_length = CIGI2_PACKET_SIZE_HEIGHT_ABOVE_TERRAIN_RESPONSE;
        } else if ( packet_id == CIGI2_PACKET_ID_LINE_OF_SIGHT_RESPONSE ) {
            hf_cigi2_packet = hf_cigi2_line_of_sight_response;
            packet_length = CIGI2_PACKET_SIZE_LINE_OF_SIGHT_RESPONSE;
        } else if ( packet_id == CIGI2_PACKET_ID_COLLISION_DETECTION_SEGMENT_RESPONSE ) {
            hf_cigi2_packet = hf_cigi2_collision_detection_segment_response;
            packet_length = CIGI2_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_RESPONSE;
        } else if ( packet_id == CIGI2_PACKET_ID_SENSOR_RESPONSE ) {
            hf_cigi2_packet = hf_cigi2_sensor_response;
            packet_length = CIGI2_PACKET_SIZE_SENSOR_RESPONSE;
        } else if ( packet_id == CIGI2_PACKET_ID_HEIGHT_OF_TERRAIN_RESPONSE ) {
            hf_cigi2_packet = hf_cigi2_height_of_terrain_response;
            packet_length = CIGI2_PACKET_SIZE_HEIGHT_OF_TERRAIN_RESPONSE;
        } else if ( packet_id == CIGI2_PACKET_ID_COLLISION_DETECTION_VOLUME_RESPONSE ) {
            hf_cigi2_packet = hf_cigi2_collision_detection_volume_response;
            packet_length = CIGI2_PACKET_SIZE_COLLISION_DETECTION_VOLUME_RESPONSE;
        } else if ( packet_id == CIGI2_PACKET_ID_IMAGE_GENERATOR_MESSAGE ) {
            hf_cigi2_packet = hf_cigi2_image_generator_message;
            packet_length = packet_size;
        } else if ( packet_id >= CIGI2_PACKET_ID_USER_DEFINABLE_MIN && packet_id <= CIGI2_PACKET_ID_USER_DEFINABLE_MAX ) {
            hf_cigi2_packet = hf_cigi2_user_definable;
            packet_length = packet_size;
        } else {
            hf_cigi2_packet = hf_cigi_unknown;
            packet_length = packet_size;
        }
        tipacket = proto_tree_add_none_format(cigi_tree, hf_cigi2_packet, tvb, offset, packet_length,
                                              "%s (%i bytes)",
                                              val_to_str_ext_const(packet_id, &cigi2_packet_id_vals_ext, "Unknown"),
                                              packet_length);

        cigi_packet_tree = proto_item_add_subtree(tipacket, ett_cigi);

        /* In CIGI versions < 4 the first byte of a packet is the packet ID.
         * The second byte is the size of the packet (in bytes). */
        init_offset = offset;
        proto_tree_add_item(cigi_packet_tree, hf_cigi2_packet_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        ti = proto_tree_add_item(cigi_packet_tree, hf_cigi_packet_size, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (packet_size < 2) {
            expert_add_info(pinfo, ti, &ei_cigi_invalid_len);
            break;
        }
        offset++;
        /* If packet_size != packet_len for the fixed size packet IDs, attempt
         * to dissect normally then add an expert info and abort afterwards below. */
        next_tvb = tvb_new_subset_length(tvb, offset, packet_size - 2);

        switch(packet_id)
        {
        case CIGI2_PACKET_ID_IG_CONTROL:
            offset = cigi2_add_ig_control(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_ENTITY_CONTROL:
            offset = cigi2_add_entity_control(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_COMPONENT_CONTROL:
            offset = cigi2_add_component_control(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_ARTICULATED_PARTS_CONTROL:
            offset = cigi2_add_articulated_parts_control(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_RATE_CONTROL:
            offset = cigi2_add_rate_control(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_ENVIRONMENT_CONTROL:
            offset = cigi2_add_environment_control(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_WEATHER_CONTROL:
            offset = cigi2_add_weather_control(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_VIEW_CONTROL:
            offset = cigi2_add_view_control(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_SENSOR_CONTROL:
            offset = cigi2_add_sensor_control(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_TRAJECTORY_DEFINITION:
            offset = cigi2_add_trajectory_definition(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_SPECIAL_EFFECT_DEFINITION:
            offset = cigi2_add_special_effect_definition(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_VIEW_DEFINITION:
            offset = cigi2_add_view_definition(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION:
            offset = cigi2_add_collision_detection_segment_definition(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION:
            offset = cigi2_add_collision_detection_volume_definition(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_HEIGHT_ABOVE_TERRAIN_REQUEST:
            offset = cigi2_add_height_above_terrain_request(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_LINE_OF_SIGHT_OCCULT_REQUEST:
            offset = cigi2_add_line_of_sight_occult_request(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_LINE_OF_SIGHT_RANGE_REQUEST:
            offset = cigi2_add_line_of_sight_range_request(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_HEIGHT_OF_TERRAIN_REQUEST:
            offset = cigi2_add_height_of_terrain_request(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_START_OF_FRAME:
            offset = cigi2_add_start_of_frame(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_HEIGHT_ABOVE_TERRAIN_RESPONSE:
            offset = cigi2_add_height_above_terrain_response(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_LINE_OF_SIGHT_RESPONSE:
            offset = cigi2_add_line_of_sight_response(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_COLLISION_DETECTION_SEGMENT_RESPONSE:
            offset = cigi2_add_collision_detection_segment_response(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_SENSOR_RESPONSE:
            offset = cigi2_add_sensor_response(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_HEIGHT_OF_TERRAIN_RESPONSE:
            offset = cigi2_add_height_of_terrain_response(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_COLLISION_DETECTION_VOLUME_RESPONSE:
            offset = cigi2_add_collision_detection_volume_response(tvb, cigi_packet_tree, offset);
            break;
        case CIGI2_PACKET_ID_IMAGE_GENERATOR_MESSAGE:
            offset = cigi2_add_image_generator_message(tvb, cigi_packet_tree, offset);
            break;
        default:
            offset = cigi_add_data(next_tvb, cigi_packet_tree, 0);
            break;
        }

        if (offset-init_offset != packet_length) {
            proto_tree_add_expert(cigi_packet_tree, pinfo, &ei_cigi_invalid_len, tvb, init_offset, offset-init_offset);
            break;
        }
    }
}

/* Create the tree for CIGI 3 */
static void
cigi3_add_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cigi_tree)
{
    int offset = 0;
    int length = 0;
    int init_offset = 0;

    int packet_id = 0;
    int packet_size = 0;
    int packet_length = 0;
    uint16_t byte_swap = 0;

    proto_tree* cigi_packet_tree = NULL;
    proto_item* tipacket, *ti;
    tvbuff_t* next_tvb;
    int hf_cigi3_packet;

    length = tvb_reported_length(tvb);

    /* Each iteration through this loop is meant to be a separate cigi packet
     * therefore it is okay to assume that at the top of this look we are given
     * a new packet to dissect. */
    while ( offset < length ) {

        packet_id = tvb_get_uint8(tvb, offset);
        packet_size = tvb_get_uint8(tvb, offset + 1);
        byte_swap = tvb_get_ntohs(tvb, offset + 6);

        /* If we have the start of frame or IG Control packet set the version */
        if ( ( packet_id == CIGI3_PACKET_ID_IG_CONTROL || packet_id == CIGI3_PACKET_ID_START_OF_FRAME ) && global_cigi_version == CIGI_VERSION_FROM_PACKET ) {
            cigi_version = tvb_get_uint8(tvb, 2);

            /* CIGI Minor Version first appeared in CIGI 3.2. Note: It is in a
             * different location in IG Control vs Start of Frame. */
            if ( packet_size == CIGI3_2_PACKET_SIZE_IG_CONTROL && packet_id == CIGI3_PACKET_ID_IG_CONTROL ) {
               cigi_minor_version = tvb_get_uint8(tvb, 4) >> 4;
            } else if ( packet_size == CIGI3_2_PACKET_SIZE_START_OF_FRAME && packet_id == CIGI3_PACKET_ID_START_OF_FRAME ) {
               cigi_minor_version = tvb_get_uint8(tvb, 5) >> 4;
            } else {
               /* CIGI version prior to 3.2 */
               cigi_minor_version = 0;
            }
        }

        /* If we have the SOF or IG Control packet set the byte order */
        if ( ( packet_id == CIGI3_PACKET_ID_IG_CONTROL || packet_id == CIGI3_PACKET_ID_START_OF_FRAME ) && global_cigi_byte_order == CIGI_BYTE_ORDER_FROM_PACKET ) {
            if ( byte_swap == CIGI3_BYTE_SWAP_BIG_ENDIAN ) {
                cigi_byte_order = ENC_BIG_ENDIAN;
            } else if ( byte_swap == CIGI3_BYTE_SWAP_LITTLE_ENDIAN ) {
                cigi_byte_order = ENC_LITTLE_ENDIAN;
            } else {
                /* Assume we want Big-Endian byte order */
                cigi_byte_order = ENC_BIG_ENDIAN;
            }
        }

        /* Add the subtree for the packet */
        if ( packet_id == CIGI3_PACKET_ID_IG_CONTROL && cigi_minor_version == 2 ) {
            hf_cigi3_packet = hf_cigi3_ig_control;
            packet_length = CIGI3_2_PACKET_SIZE_IG_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_IG_CONTROL && cigi_minor_version == 3 ) {
            hf_cigi3_packet = hf_cigi3_ig_control;
            packet_length = CIGI3_3_PACKET_SIZE_IG_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_IG_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_ig_control;
            packet_length = CIGI3_PACKET_SIZE_IG_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_ENTITY_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_entity_control;
            packet_length = CIGI3_PACKET_SIZE_ENTITY_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_CONFORMAL_CLAMPED_ENTITY_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_conformal_clamped_entity_control;
            packet_length = CIGI3_PACKET_SIZE_CONFORMAL_CLAMPED_ENTITY_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_COMPONENT_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_component_control;
            packet_length = CIGI3_PACKET_SIZE_COMPONENT_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_SHORT_COMPONENT_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_short_component_control;
            packet_length = CIGI3_PACKET_SIZE_SHORT_COMPONENT_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_ARTICULATED_PART_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_articulated_part_control;
            packet_length = CIGI3_PACKET_SIZE_ARTICULATED_PART_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_SHORT_ARTICULATED_PART_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_short_articulated_part_control;
            packet_length = CIGI3_PACKET_SIZE_SHORT_ARTICULATED_PART_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_RATE_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_rate_control;
            packet_length = CIGI3_PACKET_SIZE_RATE_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_CELESTIAL_SPHERE_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_celestial_sphere_control;
            packet_length = CIGI3_PACKET_SIZE_CELESTIAL_SPHERE_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_ATMOSPHERE_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_atmosphere_control;
            packet_length = CIGI3_PACKET_SIZE_ATMOSPHERE_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_ENVIRONMENTAL_REGION_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_environmental_region_control;
            packet_length = CIGI3_PACKET_SIZE_ENVIRONMENTAL_REGION_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_WEATHER_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_weather_control;
            packet_length = CIGI3_PACKET_SIZE_WEATHER_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_MARITIME_SURFACE_CONDITIONS_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_maritime_surface_conditions_control;
            packet_length = CIGI3_PACKET_SIZE_MARITIME_SURFACE_CONDITIONS_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_WAVE_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_wave_control;
            packet_length = CIGI3_PACKET_SIZE_WAVE_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_terrestrial_surface_conditions_control;
            packet_length = CIGI3_PACKET_SIZE_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_VIEW_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_view_control;
            packet_length = CIGI3_PACKET_SIZE_VIEW_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_SENSOR_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_sensor_control;
            packet_length = CIGI3_PACKET_SIZE_SENSOR_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_MOTION_TRACKER_CONTROL ) {
            hf_cigi3_packet = hf_cigi3_motion_tracker_control;
            packet_length = CIGI3_PACKET_SIZE_MOTION_TRACKER_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_EARTH_REFERENCE_MODEL_DEFINITION ) {
            hf_cigi3_packet = hf_cigi3_earth_reference_model_definition;
            packet_length = CIGI3_PACKET_SIZE_EARTH_REFERENCE_MODEL_DEFINITION;
        } else if ( packet_id == CIGI3_PACKET_ID_TRAJECTORY_DEFINITION ) {
            hf_cigi3_packet = hf_cigi3_trajectory_definition;
            packet_length = CIGI3_PACKET_SIZE_TRAJECTORY_DEFINITION;
        } else if ( packet_id == CIGI3_PACKET_ID_VIEW_DEFINITION ) {
            hf_cigi3_packet = hf_cigi3_view_definition;
            packet_length = CIGI3_PACKET_SIZE_VIEW_DEFINITION;
        } else if ( packet_id == CIGI3_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION ) {
            hf_cigi3_packet = hf_cigi3_collision_detection_segment_definition;
            packet_length = CIGI3_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_DEFINITION;
        } else if ( packet_id == CIGI3_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION ) {
            hf_cigi3_packet = hf_cigi3_collision_detection_volume_definition;
            packet_length = CIGI3_PACKET_SIZE_COLLISION_DETECTION_VOLUME_DEFINITION;
        } else if ( packet_id == CIGI3_PACKET_ID_HAT_HOT_REQUEST ) {
            hf_cigi3_packet = hf_cigi3_hat_hot_request;
            packet_length = CIGI3_PACKET_SIZE_HAT_HOT_REQUEST;
        } else if ( packet_id == CIGI3_PACKET_ID_LINE_OF_SIGHT_SEGMENT_REQUEST ) {
            hf_cigi3_packet = hf_cigi3_line_of_sight_segment_request;
            packet_length = CIGI3_PACKET_SIZE_LINE_OF_SIGHT_SEGMENT_REQUEST;
        } else if ( packet_id == CIGI3_PACKET_ID_LINE_OF_SIGHT_VECTOR_REQUEST ) {
            hf_cigi3_packet = hf_cigi3_line_of_sight_vector_request;
            packet_length = CIGI3_PACKET_SIZE_LINE_OF_SIGHT_VECTOR_REQUEST;
        } else if ( packet_id == CIGI3_PACKET_ID_POSITION_REQUEST ) {
            hf_cigi3_packet = hf_cigi3_position_request;
            packet_length = CIGI3_PACKET_SIZE_POSITION_REQUEST;
        } else if ( packet_id == CIGI3_PACKET_ID_ENVIRONMENTAL_CONDITIONS_REQUEST ) {
            hf_cigi3_packet = hf_cigi3_environmental_conditions_request;
            packet_length = CIGI3_PACKET_SIZE_ENVIRONMENTAL_CONDITIONS_REQUEST;
        } else if (packet_id == CIGI3_PACKET_ID_SYMBOL_SURFACE_DEFINITION) {
            hf_cigi3_packet = hf_cigi3_3_symbol_surface_definition;
            packet_length = CIGI3_PACKET_SIZE_SYMBOL_SURFACE_DEFINITION;
        } else if (packet_id == CIGI3_PACKET_ID_SYMBOL_TEXT_DEFINITION) {
            hf_cigi3_packet = hf_cigi3_3_symbol_text_definition;
            packet_length = packet_size;
        } else if (packet_id == CIGI3_PACKET_ID_SYMBOL_CIRCLE_DEFINITION) {
            hf_cigi3_packet = hf_cigi3_3_symbol_circle_definition;
            packet_length = packet_size;
        } else if (packet_id == CIGI3_PACKET_ID_SYMBOL_LINE_DEFINITION) {
            hf_cigi3_packet = hf_cigi3_3_symbol_line_definition;
            packet_length = packet_size;
        } else if (packet_id == CIGI3_PACKET_ID_SYMBOL_CLONE) {
            hf_cigi3_packet = hf_cigi3_3_symbol_clone;
            packet_length = CIGI3_PACKET_SIZE_SYMBOL_CLONE;
        } else if (packet_id == CIGI3_PACKET_ID_SYMBOL_CONTROL) {
            hf_cigi3_packet = hf_cigi3_3_symbol_control;
            packet_length = CIGI3_PACKET_SIZE_SYMBOL_CONTROL;
        } else if (packet_id == CIGI3_PACKET_ID_SHORT_SYMBOL_CONTROL) {
            hf_cigi3_packet = hf_cigi3_3_short_symbol_control;
            packet_length = CIGI3_PACKET_SIZE_SHORT_SYMBOL_CONTROL;
        } else if ( packet_id == CIGI3_PACKET_ID_START_OF_FRAME && (cigi_minor_version == 2 || cigi_minor_version == 3) ) {
            hf_cigi3_packet = hf_cigi3_2_start_of_frame;
            packet_length = CIGI3_2_PACKET_SIZE_START_OF_FRAME;
        } else if ( packet_id == CIGI3_PACKET_ID_START_OF_FRAME ) {
            hf_cigi3_packet = hf_cigi3_start_of_frame;
            packet_length = CIGI3_PACKET_SIZE_START_OF_FRAME;
        } else if ( packet_id == CIGI3_PACKET_ID_HAT_HOT_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_hat_hot_response;
            packet_length = CIGI3_PACKET_SIZE_HAT_HOT_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_HAT_HOT_EXTENDED_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_hat_hot_extended_response;
            packet_length = CIGI3_PACKET_SIZE_HAT_HOT_EXTENDED_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_LINE_OF_SIGHT_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_line_of_sight_response;
            packet_length = CIGI3_PACKET_SIZE_LINE_OF_SIGHT_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_LINE_OF_SIGHT_EXTENDED_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_line_of_sight_extended_response;
            packet_length = CIGI3_PACKET_SIZE_LINE_OF_SIGHT_EXTENDED_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_SENSOR_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_sensor_response;
            packet_length = CIGI3_PACKET_SIZE_SENSOR_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_SENSOR_EXTENDED_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_sensor_extended_response;
            packet_length = CIGI3_PACKET_SIZE_SENSOR_EXTENDED_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_POSITION_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_position_response;
            packet_length = CIGI3_PACKET_SIZE_POSITION_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_WEATHER_CONDITIONS_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_weather_conditions_response;
            packet_length = CIGI3_PACKET_SIZE_WEATHER_CONDITIONS_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_AEROSOL_CONCENTRATION_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_aerosol_concentration_response;
            packet_length = CIGI3_PACKET_SIZE_AEROSOL_CONCENTRATION_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_MARITIME_SURFACE_CONDITIONS_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_maritime_surface_conditions_response;
            packet_length = CIGI3_PACKET_SIZE_MARITIME_SURFACE_CONDITIONS_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE ) {
            hf_cigi3_packet = hf_cigi3_terrestrial_surface_conditions_response;
            packet_length = CIGI3_PACKET_SIZE_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE;
        } else if ( packet_id == CIGI3_PACKET_ID_COLLISION_DETECTION_SEGMENT_NOTIFICATION ) {
            hf_cigi3_packet = hf_cigi3_collision_detection_segment_notification;
            packet_length = CIGI3_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_NOTIFICATION;
        } else if ( packet_id == CIGI3_PACKET_ID_COLLISION_DETECTION_VOLUME_NOTIFICATION ) {
            hf_cigi3_packet = hf_cigi3_collision_detection_volume_notification;
            packet_length = CIGI3_PACKET_SIZE_COLLISION_DETECTION_VOLUME_NOTIFICATION;
        } else if ( packet_id == CIGI3_PACKET_ID_ANIMATION_STOP_NOTIFICATION ) {
            hf_cigi3_packet = hf_cigi3_animation_stop_notification;
            packet_length = CIGI3_PACKET_SIZE_ANIMATION_STOP_NOTIFICATION;
        } else if ( packet_id == CIGI3_PACKET_ID_EVENT_NOTIFICATION ) {
            hf_cigi3_packet = hf_cigi3_event_notification;
            packet_length = CIGI3_PACKET_SIZE_EVENT_NOTIFICATION;
        } else if ( packet_id == CIGI3_PACKET_ID_IMAGE_GENERATOR_MESSAGE ) {
            hf_cigi3_packet = hf_cigi3_image_generator_message;
            packet_length = packet_size;
        } else if ( packet_id >= CIGI3_PACKET_ID_USER_DEFINED_MIN && packet_id <= CIGI3_PACKET_ID_USER_DEFINED_MAX ) {
            hf_cigi3_packet = hf_cigi3_user_defined;
            packet_length = packet_size;
        } else {
            hf_cigi3_packet = hf_cigi_unknown;
            packet_length = packet_size;
        }
        tipacket = proto_tree_add_none_format(cigi_tree, hf_cigi3_packet, tvb, offset, packet_length,
                                              "%s (%i bytes)",
                                              val_to_str_ext_const(packet_id, &cigi3_packet_id_vals_ext, "Unknown"),
                                              packet_length);

        cigi_packet_tree = proto_item_add_subtree(tipacket, ett_cigi);

        /* In all CIGI3 versions the first byte of a packet is the packet ID.
         * The second byte is the size of the packet (in bytes). */
        init_offset = offset;
        proto_tree_add_item(cigi_packet_tree, hf_cigi3_packet_id, tvb, offset, 1, cigi_byte_order);
        offset++;

        ti = proto_tree_add_item(cigi_packet_tree, hf_cigi_packet_size, tvb, offset, 1, cigi_byte_order);
        /* packet_size includes the packet id (1 byte) and packet size itself (1 byte) ). */
        if (packet_size < 2) {
            expert_add_info(pinfo, ti, &ei_cigi_invalid_len);
            break;
        }
        /* If packet_size != packet_len for the fixed size packet IDs, attempt
         * to dissect normally then add an expert info and abort afterwards below. */
        offset++;
        next_tvb = tvb_new_subset_length(tvb, offset, packet_length - 2);

        int dissected = dissector_try_uint_new(cigi3_packet_id_table, packet_id,
            next_tvb, pinfo, cigi_packet_tree, false, NULL);

        if (dissected == 0) {
            dissected = cigi_add_data(next_tvb, cigi_packet_tree, 0);
        }

        offset += dissected;

        if (offset-init_offset != packet_length) {
            proto_tree_add_expert(cigi_packet_tree, pinfo, &ei_cigi_invalid_len, tvb, init_offset, offset-init_offset);
            break;
        }
    }
}

/* CIGI2 IG Control */
static int
cigi2_add_ig_control(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_ig_control_db_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_ig_control_ig_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_ig_control_tracking_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_ig_control_boresight, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_ig_control_frame_ctr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_ig_control_time_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Entity Control */
static int
cigi2_add_entity_control(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_entity_control_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_entity_control_entity_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_entity_control_attach_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_entity_control_collision_detect, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_entity_control_effect_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_entity_control_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_entity_control_parent_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_entity_control_opacity, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_entity_control_internal_temp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_entity_control_roll, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_entity_control_pitch, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_entity_control_heading, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_entity_control_alt, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_entity_control_lat, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_entity_control_lon, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

/* CIGI2 Component Control */
static int
cigi2_add_component_control(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_component_control_instance_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_component_control_component_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_component_control_component_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_component_control_component_state, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_component_control_component_val1, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_component_control_component_val2, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Articulated Part Control */
static int
cigi2_add_articulated_parts_control(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_part_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_part_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_xoff_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_yoff_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_zoff_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_roll_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_pitch_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_yaw_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_x_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_y_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_z_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_roll, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_pitch, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_articulated_parts_control_yaw, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Rate Control */
static int
cigi2_add_rate_control(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_rate_control_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_rate_control_part_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_rate_control_x_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_rate_control_y_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_rate_control_z_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_rate_control_roll_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_rate_control_pitch_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_rate_control_yaw_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Environment Control */
static int
cigi2_add_environment_control(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_environment_control_hour, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_environment_control_minute, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_environment_control_ephemeris_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_environment_control_humidity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_environment_control_modtran_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi2_environment_control_date, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_environment_control_air_temp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_environment_control_global_visibility, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_environment_control_wind_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_environment_control_wind_direction, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_environment_control_pressure, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_environment_control_aerosol, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Weather Control */
static int
cigi2_add_weather_control(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_weather_control_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_weather_control_weather_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_weather_control_scud_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_weather_control_random_winds, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_weather_control_severity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_weather_control_phenomenon_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_weather_control_air_temp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_weather_control_opacity, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_weather_control_scud_frequency, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_weather_control_coverage, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_weather_control_elevation, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_weather_control_thickness, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_weather_control_transition_band, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_weather_control_wind_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_weather_control_wind_direction, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 View Control */
static int
cigi2_add_view_control(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_view_control_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_view_control_view_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_control_view_group, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_view_control_xoff_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_control_yoff_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_control_zoff_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_control_roll_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_control_pitch_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_control_yaw_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi2_view_control_x_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_control_y_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_control_z_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_control_roll, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_control_pitch, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_control_yaw, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Sensor Control */
static int
cigi2_add_sensor_control(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_sensor_control_view_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_sensor_control_sensor_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_sensor_control_polarity, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_sensor_control_line_dropout, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_sensor_control_sensor_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_sensor_control_track_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_sensor_control_auto_gain, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_sensor_control_track_polarity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_sensor_control_gain, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_sensor_control_level, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_sensor_control_ac_coupling, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_sensor_control_noise, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Trajectory Definition */
static int
cigi2_add_trajectory_definition(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_trajectory_definition_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_trajectory_definition_acceleration, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_trajectory_definition_retardation, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_trajectory_definition_terminal_velocity, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Special Effect Definition */
static int
cigi2_add_special_effect_definition(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_seq_direction, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_color_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_red, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_green, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_blue, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_float(tree, hf_cigi2_special_effect_definition_x_scale, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_special_effect_definition_y_scale, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_special_effect_definition_z_scale, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_special_effect_definition_time_scale, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_spare, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_effect_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_separation, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_burst_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_special_effect_definition_duration, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 View Definition */
static int
cigi2_add_view_definition(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_view_definition_view_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_definition_view_group, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_view_definition_view_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_definition_pixel_rep, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_definition_mirror, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_view_definition_tracker_assign, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_definition_near_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_definition_far_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_definition_left_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_definition_right_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_definition_top_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_view_definition_bottom_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_definition_fov_near, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_definition_fov_far, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_definition_fov_left, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_definition_fov_right, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_definition_fov_top, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_view_definition_fov_bottom, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Collision Detection Segment Definition */
static int
cigi2_add_collision_detection_segment_definition(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_definition_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_definition_segment_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_definition_segment_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_definition_collision_mask, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_segment_definition_x_start, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_segment_definition_y_start, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_segment_definition_z_start, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_segment_definition_x_end, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_segment_definition_y_end, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_segment_definition_z_end, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    return offset;
}

/* CIGI2 Collision Detection Volume Definition*/
static int
cigi2_add_collision_detection_volume_definition(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_collision_detection_volume_definition_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_volume_definition_volume_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_collision_detection_volume_definition_volume_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_volume_definition_x_offset, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_volume_definition_y_offset, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_volume_definition_z_offset, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_volume_definition_height, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_volume_definition_width, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    proto_tree_add_float(tree, hf_cigi2_collision_detection_volume_definition_depth, tvb, offset, 2, cigi_get_fixed_point(tvb, offset, ENC_BIG_ENDIAN));
    offset += 2;

    return offset;
}

/* CIGI2 Height Above Terrain Request*/
static int
cigi2_add_height_above_terrain_request(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_height_above_terrain_request_hat_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 6;

    proto_tree_add_item(tree, hf_cigi2_height_above_terrain_request_alt, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_height_above_terrain_request_lat, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_height_above_terrain_request_lon, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

/* CIGI2 Line of Sight Occult Request */
static int
cigi2_add_line_of_sight_occult_request(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_line_of_sight_occult_request_los_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 6;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_occult_request_source_alt, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_occult_request_source_lat, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_occult_request_source_lon, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_occult_request_dest_alt, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_occult_request_dest_lat, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_occult_request_dest_lon, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

/* CIGI2 Line of Sight Range Request */
static int
cigi2_add_line_of_sight_range_request(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_line_of_sight_range_request_los_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_range_request_azimuth, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_range_request_elevation, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_range_request_min_range, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_range_request_max_range, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_range_request_source_alt, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_range_request_source_lat, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_range_request_source_lon, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

/* CIGI2 Height of Terrain Request */
static int
cigi2_add_height_of_terrain_request(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_height_of_terrain_request_hot_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 6;

    proto_tree_add_item(tree, hf_cigi2_height_of_terrain_request_lat, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_height_of_terrain_request_lon, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

/* CIGI2 Start of Frame */
static int
cigi2_add_start_of_frame(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_start_of_frame_db_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_start_of_frame_ig_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_start_of_frame_ig_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi2_start_of_frame_frame_ctr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_start_of_frame_time_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Height Above Terrain Response */
static int
cigi2_add_height_above_terrain_response(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_height_above_terrain_response_hat_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_height_above_terrain_response_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_height_above_terrain_response_material_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_height_above_terrain_response_alt, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

/* CIGI2 Line of Sight Response */
static int
cigi2_add_line_of_sight_response(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_line_of_sight_response_los_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_response_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_line_of_sight_response_occult_response, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_response_material_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_response_range, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_response_alt, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_response_lat, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_line_of_sight_response_lon, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

/* CIGI2 Collision Detection Segment Response */
static int
cigi2_add_collision_detection_segment_response(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_response_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_response_segment_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_response_contact, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_response_contacted_entity, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_response_material_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_response_collision_x, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_response_collision_y, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_segment_response_collision_z, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* CIGI2 Sensor Response */
static int
cigi2_add_sensor_response(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_sensor_response_view_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_sensor_response_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_sensor_response_sensor_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_cigi2_sensor_response_x_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_sensor_response_y_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_sensor_response_x_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_sensor_response_y_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/* CIGI2 Height of Terrain Response */
static int
cigi2_add_height_of_terrain_response(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_height_of_terrain_response_hot_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_height_of_terrain_response_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi2_height_of_terrain_response_material_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi2_height_of_terrain_response_alt, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

/* CIGI2 Collision Detection Volume Response */
static int
cigi2_add_collision_detection_volume_response(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_cigi2_collision_detection_volume_response_entity_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_volume_response_volume_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cigi2_collision_detection_volume_response_contact, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_collision_detection_volume_response_contact_entity, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/* CIGI2 Image Generator Message */
static int
cigi2_add_image_generator_message(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint8_t packet_size = 0;

    packet_size = tvb_get_uint8(tvb, offset-1);

    /* An image generator packet cannot be less than 4 bytes ( because every cigi packet
     * has a packet id (1 byte) and a packet size (1 byte) ). */
    if ( packet_size < 4 )
        return -1;

    proto_tree_add_item(tree, hf_cigi2_image_generator_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi2_image_generator_message_message, tvb, offset, packet_size-4, ENC_ASCII);
    offset += packet_size-4;

    return offset;
}

/* CIGI3 IG Control */
static int
cigi3_add_ig_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi_version, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_ig_control_db_number, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_ig_control_ig_mode, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_ig_control_timestamp_valid, tvb, offset, 1, cigi_byte_order);
    if (cigi_minor_version >= 3) {
        proto_tree_add_item(tree, hf_cigi3_3_ig_control_extrapolation_enable, tvb, offset, 1, cigi_byte_order);
    }
    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_ig_control_minor_version, tvb, offset, 1, cigi_byte_order);
    }
    offset += 2;

    /* Get the Byte Swap in Big-Endian so that we can display whether the value
     * is big-endian or little-endian to the user */
    proto_tree_add_item(tree, hf_cigi3_byte_swap, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_ig_control_host_frame_number, tvb, offset, 4, cigi_byte_order);
    }
    else {
        proto_tree_add_item(tree, hf_cigi3_ig_control_frame_ctr, tvb, offset, 4, cigi_byte_order);
    }
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_ig_control_timestamp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_ig_control_last_ig_frame_number, tvb, offset, 4, cigi_byte_order);
        offset += 8;
    }

    return offset;
}

/* CIGI3 Entity Control */
static int
cigi3_add_entity_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_entity_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_entity_control_entity_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_entity_control_attach_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_entity_control_collision_detection_request, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_entity_control_inherit_alpha, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_entity_control_ground_ocean_clamp, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_entity_control_animation_direction, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_entity_control_animation_loop_mode, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_entity_control_animation_state, tvb, offset, 1, cigi_byte_order);
    if (cigi_minor_version >= 3) {
        proto_tree_add_item(tree, hf_cigi3_3_entity_control_extrapolation_enable, tvb, offset, 1, cigi_byte_order);
    }
    offset++;

    proto_tree_add_item(tree, hf_cigi3_entity_control_alpha, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_entity_control_entity_type, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_entity_control_parent_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_entity_control_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_entity_control_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_entity_control_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_entity_control_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_entity_control_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_entity_control_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Entity Control */
static int
cigi4_add_entity_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi4_entity_control_entity_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_entity_control_collision_reporting_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_entity_control_inherit_alpha, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_entity_control_smooting_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_entity_control_extended_entity_type, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_entity_control_alpha, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_entity_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_entity_control_entity_kind, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_entity_control_entity_domain, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_entity_control_entity_country, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_entity_control_entity_category, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_entity_control_entity_subcategory, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_entity_control_entity_specific, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_entity_control_entity_extra, tvb, offset, 1, cigi_byte_order);
    offset++;

    return offset;
}

/* CIGI4 Animation Control */
static int
cigi4_add_animation_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi4_animation_control_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_animation_control_frame_position_reset, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_animation_control_loop_mode, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_animation_control_inherit_alpha, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_animation_control_alpha, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_animation_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_animation_control_animation_id, tvb, offset, 2, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_animation_control_animation_speed, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}


/* CIGI3 Conformal Clamped Entity Control */
static int
cigi3_add_conformal_clamped_entity_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_conformal_clamped_entity_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_conformal_clamped_entity_control_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_conformal_clamped_entity_control_lat, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_conformal_clamped_entity_control_lon, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Component Control */
static int
cigi3_add_component_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_component_control_component_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_component_control_instance_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    if (cigi_minor_version >= 3) {
        proto_tree_add_item(tree, hf_cigi3_3_component_control_component_class, tvb, offset, 1, cigi_byte_order);
    } else {
        proto_tree_add_item(tree, hf_cigi3_component_control_component_class, tvb, offset, 1, cigi_byte_order);
    }
    offset++;

    proto_tree_add_item(tree, hf_cigi3_component_control_component_state, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_3, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_4, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_5, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_6, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI3 Short Component Control */
static int
cigi3_add_short_component_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_short_component_control_component_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_short_component_control_instance_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    if (cigi_minor_version >= 3) {
        proto_tree_add_item(tree, hf_cigi3_3_short_component_control_component_class, tvb, offset, 1, cigi_byte_order);
    } else {
        proto_tree_add_item(tree, hf_cigi3_short_component_control_component_class, tvb, offset, 1, cigi_byte_order);
    }
    offset++;

    proto_tree_add_item(tree, hf_cigi3_short_component_control_component_state, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_short_component_control_data_1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_short_component_control_data_2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Short Component Control */
static int
cigi4_add_short_component_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_short_component_control_component_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_short_component_control_component_class, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_short_component_control_component_state, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_short_component_control_instance_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    //reserved
    offset += 6;

    proto_tree_add_item(tree, hf_cigi3_short_component_control_data_1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_short_component_control_data_2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}


/* CIGI3 Articulated Part Control */
static int
cigi3_add_articulated_part_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_part_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_part_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_xoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_yoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_zoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_roll_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_pitch_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_yaw_enable, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_xoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_yoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_zoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Articulated Part Control */
static int
cigi4_add_articulated_part_control(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree* field_tree;
    proto_item* tf;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_part_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    //enabled Flags
    tf = proto_tree_add_item(tree, hf_cigi4_articulated_part_control_part_enable_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_articulated_part_control_part_enable_flags);

    proto_tree_add_item(field_tree, hf_cigi3_articulated_part_control_part_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_articulated_part_control_xoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_articulated_part_control_yoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_articulated_part_control_zoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_articulated_part_control_roll_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_articulated_part_control_pitch_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_articulated_part_control_yaw_enable, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_xoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_yoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_zoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_articulated_part_control_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}


/* CIGI3 Short Articulated Part Control */
static int
cigi3_add_short_articulated_part_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_part_id_1, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_part_id_2, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_dof_select_1, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_dof_select_2, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_part_enable_1, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_part_enable_2, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_dof_1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_dof_2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Short Articulated Part Control */
static int
cigi4_add_short_articulated_part_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree* field_tree;
    proto_item* tf;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_part_id_1, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_part_id_2, tvb, offset, 1, cigi_byte_order);
    offset++;

    //enabled Flags
    tf = proto_tree_add_item(tree, hf_cigi4_short_articulated_part_control_part_enable_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_short_articulated_part_control_part_enable_flags);

    proto_tree_add_item(field_tree, hf_cigi3_short_articulated_part_control_dof_select_1, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_short_articulated_part_control_dof_select_2, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_short_articulated_part_control_part_enable_1, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_short_articulated_part_control_part_enable_2, tvb, offset, 1, cigi_byte_order);
    offset++;

    //reserved
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_dof_1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_short_articulated_part_control_dof_2, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}


/* CIGI3 Rate Control */
static int
cigi3_add_rate_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_rate_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_rate_control_part_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_rate_control_apply_to_part, tvb, offset, 1, cigi_byte_order);
    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_rate_control_coordinate_system, tvb, offset, 1, cigi_byte_order);
    }
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_rate_control_x_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_rate_control_y_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_rate_control_z_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_rate_control_roll_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_rate_control_pitch_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_rate_control_yaw_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Velocity Control */
static int
cigi4_add_velocity_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree* field_tree;
    proto_item* tf;

    proto_tree_add_item(tree, hf_cigi4_velocity_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_velocity_control_part_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    //Flags
    tf = proto_tree_add_item(tree, hf_cigi4_velocity_control_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_velocity_control_flags);
    proto_tree_add_item(field_tree, hf_cigi4_velocity_control_apply_to_part, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi4_velocity_control_coordinate_system, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_velocity_control_x_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_velocity_control_y_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_velocity_control_z_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_velocity_control_roll_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_velocity_control_pitch_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_velocity_control_yaw_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}


/* CIGI3 Celestial Sphere Control */
static int
cigi3_add_celestial_sphere_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_hour, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_minute, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_ephemeris_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_sun_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_moon_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_star_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_date_time_valid, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_date, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_star_intensity, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Celestial Sphere Control */
static int
cigi4_add_celestial_sphere_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree* field_tree;
    proto_item* tf;

    //Enabled Flags
    tf = proto_tree_add_item(tree, hf_cigi4_celestial_sphere_control_enable_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_celestial_sphere_control_flags);
    proto_tree_add_item(field_tree, hf_cigi3_celestial_sphere_control_ephemeris_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_celestial_sphere_control_sun_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_celestial_sphere_control_moon_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_celestial_sphere_control_star_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_celestial_sphere_control_date_time_valid, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_hour, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_minute, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_celestial_sphere_control_seconds, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_celestial_sphere_control_date, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_celestial_sphere_control_star_intensity, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    //reserved
    offset += 4;

    return offset;
}



/* CIGI3 Atmosphere Control */
static int
cigi3_add_atmosphere_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_atmospheric_model_enable, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_humidity, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_air_temp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_visibility_range, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_horiz_wind, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_vert_wind, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_wind_direction, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_barometric_pressure, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Atmosphere Control */
static int
cigi4_add_atmosphere_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_atmospheric_model_enable, tvb, offset, 1, cigi_byte_order);

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_humidity, tvb, offset, 1, cigi_byte_order);
    offset++;

    //reserved
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_air_temp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_visibility_range, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_horiz_wind, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_vert_wind, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_wind_direction, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_atmosphere_control_barometric_pressure, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}


/* CIGI3 Environmental Region Control */
static int
cigi3_add_environmental_region_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_region_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_region_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_merge_weather, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_merge_aerosol, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_merge_maritime, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_merge_terrestrial, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_lat, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_lon, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_size_x, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_size_y, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_corner_radius, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_rotation, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_transition_perimeter, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}


/* CIGI4 Environmental Region Control */
static int
cigi4_add_environmental_region_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_region_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_merge_weather, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_merge_aerosol, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_merge_maritime, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_merge_terrestrial, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_region_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_lat, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_lon, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_size_x, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_size_y, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_corner_radius, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_rotation, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_environmental_region_control_transition_perimeter, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}


/* CIGI3 Weather Control */
static int
cigi3_add_weather_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_weather_control_entity_region_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_weather_control_layer_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_weather_control_humidity, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_weather_control_weather_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_weather_control_scud_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_weather_control_random_winds_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_weather_control_random_lightning_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_weather_control_cloud_type, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_weather_control_scope, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_weather_control_severity, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_weather_control_air_temp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_visibility_range, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_scud_frequency, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_coverage, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_base_elevation, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_thickness, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_transition_band, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_horiz_wind, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_vert_wind, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_wind_direction, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_barometric_pressure, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_aerosol_concentration, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}


/* CIGI4 Weather Control */
static int
cigi4_add_weather_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_weather_control_layer_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_weather_control_humidity, tvb, offset, 1, cigi_byte_order);
    offset++;

    //flags
    proto_tree_add_item(tree, hf_cigi3_weather_control_weather_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_weather_control_scud_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_weather_control_random_winds_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_weather_control_random_lightning_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_weather_control_cloud_type, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_weather_control_scope, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_weather_control_severity, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_weather_control_top_scud_enable, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_weather_control_entity_region_id, tvb, offset, 2, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_air_temp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_visibility_range, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_scud_frequency, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_coverage, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_base_elevation, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_thickness, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_transition_band, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_horiz_wind, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_vert_wind, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_wind_direction, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_barometric_pressure, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_control_aerosol_concentration, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_weather_control_top_scud_freq, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_weather_control_top_transition_band, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    //reserved
    offset += 4;

    return offset;
}

/* CIGI3 Maritime Surface Conditions Control */
static int
cigi3_add_maritime_surface_conditions_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_entity_region_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_surface_conditions_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_whitecap_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_scope, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_sea_surface_height, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_surface_water_temp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_surface_clarity, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Maritime Surface Conditions Control */
static int
cigi4_add_maritime_surface_conditions_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_surface_conditions_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_whitecap_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_scope, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_entity_region_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_sea_surface_height, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_surface_water_temp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_control_surface_clarity, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Wave Control */
static int
cigi3_add_wave_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_wave_control_entity_region_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_wave_control_wave_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_wave_control_wave_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_wave_control_scope, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_wave_control_breaker_type, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_wave_control_height, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_wave_control_wavelength, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_wave_control_period, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_wave_control_direction, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_wave_control_phase_offset, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_wave_control_leading, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Wave Control */
static int
cigi4_add_wave_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_wave_control_wave_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_wave_control_wave_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_wave_control_scope, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_wave_control_breaker_type, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_wave_control_entity_region_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_wave_control_height, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_wave_control_wavelength, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_wave_control_period, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_wave_control_direction, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_wave_control_phase_offset, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_wave_control_leading, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI3 Terrestrial Surface Conditions Control */
static int
cigi3_add_terrestrial_surface_conditions_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_entity_region_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_surface_condition_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_surface_condition_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_scope, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_severity, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_coverage, tvb, offset, 1, cigi_byte_order);
    offset++;

    return offset;
}

/* CIGI4 Terrestrial Surface Conditions Control */
static int
cigi4_add_terrestrial_surface_conditions_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_entity_region_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_surface_condition_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_scope, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_severity, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_coverage, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_control_surface_condition_id, tvb, offset, 2, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 View Control */
static int
cigi3_add_view_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_view_control_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_view_control_group_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_view_control_xoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_control_yoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_control_zoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_control_roll_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_control_pitch_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_control_yaw_enable, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_view_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_view_control_xoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_control_yoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_control_zoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_control_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_control_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_control_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 View Control */
static int
cigi4_add_view_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree* field_tree;
    proto_item* tf;

    proto_tree_add_item(tree, hf_cigi3_view_control_group_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    //Flags
    tf = proto_tree_add_item(tree, hf_cigi4_view_control_enable_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_view_control_enable_flags);
    proto_tree_add_item(field_tree, hf_cigi3_view_control_xoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_view_control_yoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_view_control_zoff_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_view_control_roll_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_view_control_pitch_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_view_control_yaw_enable, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_view_control_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_view_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    //reserved
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_view_control_xoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_control_yoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_control_zoff, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_control_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_control_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_control_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Sensor Control */
static int
cigi3_add_sensor_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_sensor_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_sensor_on_off, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_control_polarity, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_control_line_dropout_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_control_auto_gain, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_control_track_white_black, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_control_track_mode, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_response_type, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_gain, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_level, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_ac_coupling, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_noise, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Sensor Control */
static int
cigi4_add_sensor_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_sensor_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_sensor_on_off, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_control_polarity, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_control_line_dropout_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_control_auto_gain, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_control_track_white_black, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_control_track_mode, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_response_type, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_gain, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_level, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_ac_coupling, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_control_noise, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Motion Tracker Control */
static int
cigi3_add_motion_tracker_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_view_group_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_tracker_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_tracker_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_boresight_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_x_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_y_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_z_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_roll_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_pitch_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_yaw_enable, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_view_group_select, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    return offset;
}

/* CIGI4 Motion Tracker Control */
static int
cigi4_add_motion_tracker_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_tracker_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_tracker_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_boresight_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_x_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_y_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_z_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_roll_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_pitch_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_yaw_enable, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_view_group_select, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_motion_tracker_control_view_group_id, tvb, offset, 2, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Earth Reference Model Definition */
static int
cigi3_add_earth_reference_model_definition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_earth_reference_model_definition_erm_enable, tvb, offset, 1, cigi_byte_order);
    offset += 6;

    proto_tree_add_item(tree, hf_cigi3_earth_reference_model_definition_equatorial_radius, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_earth_reference_model_definition_flattening, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Earth Reference Model Definition */
static int
cigi4_add_earth_reference_model_definition(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_earth_reference_model_definition_erm_enable, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_earth_reference_model_definition_equatorial_radius, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_earth_reference_model_definition_flattening, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Trajectory Definition */
static int
cigi3_add_trajectory_definition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_trajectory_definition_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_trajectory_definition_acceleration_x, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_trajectory_definition_acceleration_y, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_trajectory_definition_acceleration_z, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_trajectory_definition_retardation_rate, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_trajectory_definition_terminal_velocity, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Acceleration Control */
static int
cigi4_add_acceleration_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi4_acceleration_control_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_acceleration_control_articulated_part_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_acceleration_control_apply_to_part, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_acceleration_control_coord_system, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_acceleration_control_acceleration_x, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_acceleration_control_acceleration_y, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_acceleration_control_acceleration_z, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_acceleration_control_acceleration_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_acceleration_control_acceleration_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_acceleration_control_acceleration_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}


/* CIGI3 View Definition */
static int
cigi3_add_view_definition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_view_definition_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_view_definition_group_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_view_definition_near_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_far_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_left_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_right_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_top_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_bottom_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_mirror_mode, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_view_definition_pixel_replication, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_projection_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_reorder, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_view_type, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_view_definition_near, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_far, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_left, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_right, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_top, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_bottom, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 View Definition */
static int
cigi4_add_view_definition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_view_definition_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_view_definition_group_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_view_definition_near_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_far_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_left_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_right_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_top_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_bottom_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_mirror_mode, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_view_definition_pixel_replication, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_projection_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_reorder, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_view_definition_view_type, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_near, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_far, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_left, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_right, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_top, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_view_definition_bottom, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Collision Detection Segment Definition */
static int
cigi3_add_collision_detection_segment_definition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_segment_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_segment_enable, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_x1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_y1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_z1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_x2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_y2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_z2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_material_mask, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Collision Detection Segment Definition */
static int
cigi4_add_collision_detection_segment_definition(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_segment_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_segment_enable, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_x1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_y1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_z1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_x2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_y2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_z2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_definition_material_mask, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Collision Detection Volume Definition */
static int
cigi3_add_collision_detection_volume_definition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_volume_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_volume_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_volume_type, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_x, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_y, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_z, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_radius_height, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_width, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_depth, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Collision Detection Volume Definition */
static int
cigi4_add_collision_detection_volume_definition(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_volume_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_volume_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_volume_type, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_x, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_y, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_z, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_radius_height, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_width, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_depth, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_definition_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 HAT/HOT Request */
static int
cigi3_add_hat_hot_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_hat_hot_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_coordinate_system, tvb, offset, 1, cigi_byte_order);
    offset++;

    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_hat_hot_request_update_period, tvb, offset, 1, cigi_byte_order);
    }
    offset++;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Line of Sight Segment Request */
static int
cigi3_add_line_of_sight_segment_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_los_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_source_coord, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_destination_coord, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_response_coord, tvb, offset, 1, cigi_byte_order);
    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_segment_request_destination_entity_id_valid, tvb, offset, 1, cigi_byte_order);
    }
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_alpha_threshold, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_source_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_source_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_source_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_source_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_destination_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_destination_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_destination_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_material_mask, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_segment_request_update_period, tvb, offset, 1, cigi_byte_order);
        offset += 2;

        proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_segment_request_destination_entity_id, tvb, offset, 2, cigi_byte_order);
        offset += 2;
    } else {
        offset += 4;
    }

    return offset;
}

/* CIGI4 Line of Sight Segment Request */
static int
cigi4_add_line_of_sight_segment_request(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_los_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_source_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_source_coord, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_destination_coord, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_response_coord, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_segment_request_destination_entity_id_valid, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_alpha_threshold, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_segment_request_destination_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_segment_request_update_period, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_source_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_source_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_source_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_destination_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_destination_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_destination_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_segment_request_material_mask, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Line of Sight Vector Request */
static int
cigi3_add_line_of_sight_vector_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_los_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_source_coord, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_response_coord, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_alpha, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_azimuth, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_elevation, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_min_range, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_max_range, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_source_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_source_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_source_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_material_mask, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_vector_request_update_period, tvb, offset, 1, cigi_byte_order);
    }
    offset += 4;

    return offset;
}

/* CIGI4 Line of Sight Vector Request */
static int
cigi4_add_line_of_sight_vector_request(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_los_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_source_coord, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_response_coord, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_alpha, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_vector_request_update_period, tvb, offset, 1, cigi_byte_order);
    offset += 6;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_azimuth, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_elevation, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_min_range, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_max_range, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_source_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_source_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_source_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_vector_request_material_mask, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Position Request */
static int
cigi3_add_position_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_position_request_object_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_position_request_part_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_position_request_update_mode, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_position_request_object_class, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_position_request_coord_system, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    return offset;
}


/* CIGI4 Position Request */
static int
cigi4_add_position_request(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_position_request_part_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_position_request_update_mode, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_position_request_object_class, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_position_request_coord_system, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_position_request_object_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    return offset;
}

/* CIGI3 Environmental Conditions Request */
static int
cigi3_add_environmental_conditions_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_environmental_conditions_request_type, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_environmental_conditions_request_id, tvb, offset, 1, cigi_byte_order);
    offset += 5;

    proto_tree_add_item(tree, hf_cigi3_environmental_conditions_request_lat, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_environmental_conditions_request_lon, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_environmental_conditions_request_alt, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Environmental Conditions Request */
static int
cigi4_add_environmental_conditions_request(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_environmental_conditions_request_type, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_environmental_conditions_request_id, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_environmental_conditions_request_lat, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_environmental_conditions_request_lon, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_environmental_conditions_request_alt, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3_3 Symbol Surface Definition */
static int
cigi3_3_add_symbol_surface_definition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    /* Dissect as data on versions before 3.3 */
    if (cigi_minor_version < 3) {
        return offset;
    }

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_surface_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_surface_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_attach_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_billboard, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_perspective_growth_enable, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_entity_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_xoff_left, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_yoff_right, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_zoff_top, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_yaw_bottom, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_width, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_height, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_min_u, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_max_u, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_min_v, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_max_v, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Symbol Surface Definition */
static int
cigi4_add_symbol_surface_definition(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_surface_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_entity_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_surface_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_attach_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_billboard, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_perspective_growth_enable, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_xoff_left, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_yoff_right, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_zoff_top, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_yaw_bottom, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_width, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_height, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_min_u, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_max_u, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_min_v, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_surface_definition_max_v, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3_3 Symbol Text Definition */
static int
cigi3_3_add_symbol_text_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    if (cigi_minor_version < 3) {
        return offset;
    }

    proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_alignment, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_orientation, tvb, offset, 1, cigi_byte_order);
    offset += 1;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_font_ident, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_font_size, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    if (tvb_reported_length_remaining(tvb, offset) < 2) {
        proto_tree_add_expert_format(tree, pinfo, &ei_cigi_invalid_len, tvb, 0,
            tvb_reported_length(tvb), "Insufficient room for symbol text definition");
    } else {
        proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_text, tvb, offset,
            tvb_reported_length_remaining(tvb, offset), cigi_byte_order);
    }

    return tvb_reported_length(tvb);
}

/* CIGI4 Symbol Text Definition */
static int
cigi4_add_symbol_text_definition(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_alignment, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_orientation, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_font_ident, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_font_size, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    if (tvb_reported_length_remaining(tvb, offset) < 2) {
        proto_tree_add_expert_format(tree, pinfo, &ei_cigi_invalid_len, tvb, 0,
            tvb_reported_length(tvb), "Insufficient room for symbol text definition");
    } else {
        proto_tree_add_item(tree, hf_cigi3_3_symbol_text_definition_text, tvb, offset,
            tvb_reported_length_remaining(tvb, offset), cigi_byte_order);
    }

    return tvb_reported_length(tvb);
}

/* CIGI3_3 Symbol Circle Definition */
static int
cigi3_3_add_symbol_circle_definition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    int ncircles, c;

    if (cigi_minor_version < 3) {
        return offset;
    }

    proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_drawing_style, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_stipple_pattern, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_line_width, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_stipple_pattern_length, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    ncircles = tvb_reported_length_remaining(tvb, offset) / 24;

    /* The length of tvb is determined by a 1 octet packet length value and
     * thus there should be fewer than 10 circles (CIGI 3.3 4.1.31)
     */
    DISSECTOR_ASSERT_CMPINT(ncircles, <, 10);

    for (c = 0; c < ncircles; c++) {
        proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_center_u[c], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_center_v[c], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_radius[c], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_inner_radius[c], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_start_angle[c], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_end_angle[c], tvb, offset, 4, cigi_byte_order);
        offset += 4;
    }

    return offset;
}

/* CIGI4 Symbol Circle Definition */
static int
cigi4_add_symbol_circle_definition(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree* field_tree;
    proto_item* tf;

    int ncircles, c, c_field;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_stipple_pattern, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_drawing_style, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_line_width, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_circle_definition_stipple_pattern_length, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    ncircles = tvb_reported_length_remaining(tvb, offset) / 24;

    for (c = 0; c < ncircles; c++) {
        tf = proto_tree_add_item(tree, hf_cigi4_symbol_circle_definition_circles, tvb, offset, 24, cigi_byte_order);
        proto_item_append_text(tf, " %u", c);
        field_tree = proto_item_add_subtree(tf, ett_cigi4_symbol_circle_definition_circles);

        /* XXX: The length of tvb is determined by a 2 octet packet length value and
         * thus there can be more circles than fields that are declared (unlike
         * CIGI 3). Make sure we don't have a memory error.
         */
        c_field = c % array_length(hf_cigi3_3_symbol_circle_definition_center_u);

        proto_tree_add_item(field_tree, hf_cigi3_3_symbol_circle_definition_center_u[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi3_3_symbol_circle_definition_center_v[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi3_3_symbol_circle_definition_radius[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi3_3_symbol_circle_definition_inner_radius[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi3_3_symbol_circle_definition_start_angle[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi3_3_symbol_circle_definition_end_angle[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;
    }

    return offset;
}

/* CIGI3_3 Symbol Line Definition */
static int
cigi3_3_add_symbol_line_definition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    int nvertices, v;

    if (cigi_minor_version < 3) {
        return offset;
    }

    proto_tree_add_item(tree, hf_cigi3_3_symbol_line_definition_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_line_definition_primitive_type, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_line_definition_stipple_pattern, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_line_definition_line_width, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_line_definition_stipple_pattern_length, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    nvertices = tvb_reported_length_remaining(tvb, offset) / 8;

    /* The length of tvb is determined by a 1 octet packet length value and
     * thus there should be fewer than 30 vertices (CIGI 3.3 4.1.32)
     */
    DISSECTOR_ASSERT_CMPINT(nvertices, <, 30);

    for(v=0; v<nvertices; v++) {
        proto_tree_add_item(tree, hf_cigi3_3_symbol_line_definition_vertex_u[v], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(tree, hf_cigi3_3_symbol_line_definition_vertex_v[v], tvb, offset, 4, cigi_byte_order);
        offset += 4;
    }

    return offset;
}

/* CIGI4 Symbol Polygon Definition */
static int
cigi4_add_symbol_polygon_definition(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree* field_tree;
    proto_item* tf;

    int nvertices, v, v_field;

    proto_tree_add_item(tree, hf_cigi4_symbol_polygon_definition_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_symbol_polygon_definition_stipple_pattern, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_symbol_polygon_definition_primitive_type, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_symbol_polygon_definition_line_width, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_symbol_polygon_definition_stipple_pattern_length, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    nvertices = tvb_reported_length_remaining(tvb, offset) / 8;

    for (v = 0; v < nvertices; v++) {
        tf = proto_tree_add_item(tree, hf_cigi4_symbol_polygon_definition_vertices, tvb, offset, 8, cigi_byte_order);
        proto_item_append_text(tf, "[%u]", v);
        field_tree = proto_item_add_subtree(tf, ett_cigi4_symbol_polygon_definition_vertices);

        /* XXX: The length of tvb is determined by a 2 octet packet length value and
         * thus there can be more vertices than fields that are declared (unlike
         * CIGI 3). Make sure we don't have a memory error.
         */
        v_field = v % array_length(hf_cigi4_symbol_polygon_definition_vertex_u);

        proto_tree_add_item(field_tree, hf_cigi4_symbol_polygon_definition_vertex_u[v_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_polygon_definition_vertex_v[v_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;
    }

    return offset;
}

/* CIGI3_3 Symbol Clone */
static int
cigi3_3_add_symbol_clone(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    if (cigi_minor_version < 3) {
        return offset;
    }

    proto_tree_add_item(tree, hf_cigi3_3_symbol_clone_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_clone_source_type, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_clone_source_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    return offset;
}

/* CIGI4 Symbol Clone */
static int
cigi4_add_symbol_clone(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_clone_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_clone_source_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_clone_source_type, tvb, offset, 1, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3_3 Symbol Control */
static int
cigi3_3_add_symbol_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    if (cigi_minor_version < 3) {
        return offset;
    }

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_symbol_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_attach_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_flash_control, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_inherit_color, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_parent_symbol_ident, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_surface_ident, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_layer, tvb, offset, 1, cigi_byte_order);
    offset += 1;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_flash_duty_cycle, tvb, offset, 1, cigi_byte_order);
    offset += 1;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_flash_period, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_position_u, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_position_v, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_rotation, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_red, tvb, offset, 1, cigi_byte_order);
    offset += 1;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_green, tvb, offset, 1, cigi_byte_order);
    offset += 1;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_blue, tvb, offset, 1, cigi_byte_order);
    offset += 1;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_alpha, tvb, offset, 1, cigi_byte_order);
    offset += 1;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_scale_u, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_scale_v, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Symbol Control */
static int
cigi4_add_symbol_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_parent_symbol_ident, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_symbol_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_attach_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_flash_control, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_inherit_color, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_layer, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_flash_duty_cycle, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_surface_ident, tvb, offset, 2, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_flash_period, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_position_u, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_position_v, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_rotation, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_red, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_green, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_blue, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_alpha, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_scale_u, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_symbol_control_scale_v, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3_3 Short Symbol Control */
static int
cigi3_3_add_short_symbol_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    if (cigi_minor_version < 3) {
        return offset;
    }

    uint8_t select1 = 0;
    uint8_t select2 = 0;

    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_symbol_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attach_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_flash_control, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_inherit_color, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    select1 = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attribute_select1, tvb, offset, 1, cigi_byte_order);
    offset += 1;

    select2 = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attribute_select2, tvb, offset, 1, cigi_byte_order);
    offset++;

    if (select1 == 9) {
        if (cigi_byte_order == ENC_BIG_ENDIAN) {
            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_red1, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_green1, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_blue1, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_alpha1, tvb, offset, 1, cigi_byte_order);
            offset++;
        } else {
            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_alpha1, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_blue1, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_green1, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_red1, tvb, offset, 1, cigi_byte_order);
            offset++;
        }
    } else {
        if (select1 >= 5 && select1 <= 11) {
            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attribute_value1f, tvb, offset, 4, cigi_byte_order);
        } else {
            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attribute_value1, tvb, offset, 4, cigi_byte_order);
        }
        offset += 4;
    }

    if (select2 == 9) {
        if (cigi_byte_order == ENC_BIG_ENDIAN) {
            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_red2, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_green2, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_blue2, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_alpha2, tvb, offset, 1, cigi_byte_order);
            offset++;
        } else {
            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_alpha2, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_blue2, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_green2, tvb, offset, 1, cigi_byte_order);
            offset++;

            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_red2, tvb, offset, 1, cigi_byte_order);
            offset++;
        }

    } else {
        if (select2 >= 5 && select2 <= 11) {
            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attribute_value2f, tvb, offset, 4, cigi_byte_order);
        } else {
            proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attribute_value2, tvb, offset, 4, cigi_byte_order);
        }
        offset += 4;
    }

    return offset;
}

/* CIGI4 Short Symbol Control */
static int
cigi4_add_short_symbol_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attribute_select1, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attribute_select2, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_symbol_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attach_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_flash_control, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_inherit_color, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attribute_value1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_3_short_symbol_control_attribute_value2, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Symbol Textured Circle */
static int
cigi4_add_symbol_circle_textured(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    int offset = 0;

    int ncircles, c, c_field;

    proto_tree_add_item(tree, hf_cigi4_symbol_circle_textured_definition_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_symbol_circle_textured_definition_texture_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_symbol_circle_textured_definition_filter_mode, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_symbol_circle_textured_definition_wrap, tvb, offset, 1, cigi_byte_order);
    offset += 8;

    ncircles = tvb_reported_length_remaining(tvb, offset) / 40;

    for (c = 0; c < ncircles; c++) {
        tf = proto_tree_add_item(tree, hf_cigi4_symbol_circle_textured_definition_circles, tvb, offset, 1, cigi_byte_order);
        proto_item_append_text(tf, " %u", c);
        field_tree = proto_item_add_subtree(tf, ett_cigi4_symbol_circle_textured_definition_circles);

        /* XXX: The length of tvb is determined by a 2 octet packet length value and
         * thus there can be more circles than fields that are declared (unlike
         * CIGI 3). Make sure we don't have a memory error.
         */
        c_field = c % array_length(hf_cigi4_symbol_circle_textured_definition_center_u);

        proto_tree_add_item(field_tree, hf_cigi4_symbol_circle_textured_definition_center_u[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_circle_textured_definition_center_v[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_circle_textured_definition_radius[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_circle_textured_definition_inner_radius[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_circle_textured_definition_start_angle[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_circle_textured_definition_end_angle[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_circle_textured_definition_texture_center_u[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_circle_textured_definition_texture_center_v[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_circle_textured_definition_texture_radius[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_circle_textured_definition_texture_rotation[c_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;
    }

    return offset;
}

/* CIGI4 Symbol Textured Polygon */
static int
cigi4_add_symbol_polygon_textured(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    int offset = 0;

    int nvertices, v, v_field;

    proto_tree_add_item(tree, hf_cigi4_symbol_polygon_textured_definition_symbol_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_symbol_polygon_textured_definition_texture_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_symbol_polygon_textured_definition_filter_mode, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi4_symbol_polygon_textured_definition_wrap, tvb, offset, 1, cigi_byte_order);
    offset += 8;

    nvertices = tvb_reported_length_remaining(tvb, offset) / 16;

    for (v = 0; v < nvertices; v++) {
        tf = proto_tree_add_item(tree, hf_cigi4_symbol_polygon_textured_definition_vertices, tvb, offset, 1, cigi_byte_order);
        proto_item_append_text(tf, " %u", v);
        field_tree = proto_item_add_subtree(tf, ett_cigi4_symbol_polygon_textured_definition_vertices);

        /* XXX: The length of tvb is determined by a 2 octet packet length value and
         * thus there can be more vertices than fields that are declared (unlike
         * CIGI 3). Make sure we don't have a memory error.
         */
        v_field = v % array_length(hf_cigi4_symbol_polygon_textured_definition_vertex_u);

        proto_tree_add_item(field_tree, hf_cigi4_symbol_polygon_textured_definition_vertex_u[v_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_polygon_textured_definition_vertex_v[v_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_polygon_textured_definition_texture_center_u[v_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;

        proto_tree_add_item(field_tree, hf_cigi4_symbol_polygon_textured_definition_texture_center_v[v_field], tvb, offset, 4, cigi_byte_order);
        offset += 4;
    }

    return offset;
}

/* CIGI3 Start of Frame */
static int
cigi3_add_start_of_frame(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi_version, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_start_of_frame_db_number, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_start_of_frame_ig_status, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_start_of_frame_ig_mode, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_start_of_frame_timestamp_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_start_of_frame_earth_reference_model, tvb, offset, 1, cigi_byte_order);
    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_start_of_frame_minor_version, tvb, offset, 1, cigi_byte_order);
    }
    offset++;

    /* Get the Byte Swap in Big-Endian so that we can display whether the value
     * is big-endian or little-endian to the user */
    proto_tree_add_item(tree, hf_cigi3_byte_swap, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_start_of_frame_ig_frame_number, tvb, offset, 4, cigi_byte_order);
    } else {
        proto_tree_add_item(tree, hf_cigi3_start_of_frame_frame_ctr, tvb, offset, 4, cigi_byte_order);
    }
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_start_of_frame_timestamp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_start_of_frame_last_host_frame_number, tvb, offset, 4, cigi_byte_order);
        offset += 8;
    }

    return offset;
}

/* CIGI3 HAT/HOT Response */
static int
cigi3_add_hat_hot_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_response_hat_hot_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    tf = proto_tree_add_item(tree, hf_cigi4_hat_hot_response_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_hat_hot_response_flags);
    proto_tree_add_item(field_tree, hf_cigi3_hat_hot_response_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_hat_hot_response_type, tvb, offset, 1, cigi_byte_order);
    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_hat_hot_response_host_frame_number_lsn, tvb, offset, 1, cigi_byte_order);
    }
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_response_height, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 HAT/HOT Response */
static int
cigi4_add_hat_hot_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    int offset = 0;

    tf = proto_tree_add_item(tree, hf_cigi4_hat_hot_response_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_hat_hot_response_flags);
    proto_tree_add_item(field_tree, hf_cigi3_hat_hot_response_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_hat_hot_response_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_2_hat_hot_response_host_frame_number_lsn, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_response_hat_hot_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_response_height, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}


/* CIGI3 HAT/HOT Extended Response */
static int
cigi3_add_hat_hot_extended_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_hat_hot_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    tf = proto_tree_add_item(tree, hf_cigi4_hat_hot_extended_response_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_hat_hot_extended_response_flags);
    proto_tree_add_item(field_tree, hf_cigi3_hat_hot_extended_response_valid, tvb, offset, 1, cigi_byte_order);
    if (cigi_minor_version >= 2) {
        proto_tree_add_item(field_tree, hf_cigi3_2_hat_hot_extended_response_host_frame_number_lsn, tvb, offset, 1, cigi_byte_order);
    }
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_hat, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_hot, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_material_code, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_normal_vector_azimuth, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_normal_vector_elevation, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 HAT/HOT Extended Response */
static int
cigi4_add_hat_hot_extended_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    int offset = 0;

    tf = proto_tree_add_item(tree, hf_cigi4_hat_hot_extended_response_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_hat_hot_extended_response_flags);
    proto_tree_add_item(field_tree, hf_cigi3_hat_hot_extended_response_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_2_hat_hot_extended_response_host_frame_number_lsn, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_hat_hot_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_hat, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_hot, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_material_code, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_normal_vector_azimuth, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_extended_response_normal_vector_elevation, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}


/* CIGI3 Line of Sight Response */
static int
cigi3_add_line_of_sight_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_los_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_entity_id_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_visible, tvb, offset, 1, cigi_byte_order);
    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_response_host_frame_number_lsn, tvb, offset, 1, cigi_byte_order);
    }
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_count, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_range, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Line of Sight Response */
static int
cigi4_add_line_of_sight_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_los_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_entity_id_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_visible, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_response_host_frame_number_lsn, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_count, tvb, offset, 1, cigi_byte_order);
    offset += 7;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_response_range, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Line of Sight Extended Response */
static int
cigi3_add_line_of_sight_extended_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_los_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_entity_id_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_range_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_visible, tvb, offset, 1, cigi_byte_order);
    if (cigi_minor_version >= 2) {
        proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_extended_response_host_frame_number_lsn, tvb, offset, 1, cigi_byte_order);
    } else {
        proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_intersection_coord, tvb, offset, 1, cigi_byte_order);
    }
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_response_count, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_range, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_red, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_green, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_blue, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_alpha, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_material_code, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_normal_vector_azimuth, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_normal_vector_elevation, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Line of Sight Extended Response */
static int
cigi4_add_line_of_sight_extended_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_los_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_entity_id_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_range_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_visible, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_2_line_of_sight_extended_response_host_frame_number_lsn, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_response_count, tvb, offset, 1, cigi_byte_order);
    offset += 7;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_range, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_red, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_green, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_blue, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_alpha, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_material_code, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_normal_vector_azimuth, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_line_of_sight_extended_response_normal_vector_elevation, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI3 Sensor Response */
static int
cigi3_add_sensor_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_sensor_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_sensor_status, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_gate_x_size, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_gate_y_size, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_gate_x_pos, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_gate_y_pos, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_frame_ctr, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Sensor Response */
static int
cigi4_add_sensor_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_sensor_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_sensor_status, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_gate_x_size, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_gate_y_size, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_gate_x_pos, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_gate_y_pos, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_response_frame_ctr, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI3 Sensor Extended Response */
static int
cigi3_add_sensor_extended_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_sensor_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_sensor_status, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_entity_id_valid, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_gate_x_size, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_gate_y_size, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_gate_x_pos, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_gate_y_pos, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_frame_ctr, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_track_lat, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_track_lon, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_track_alt, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Sensor Extended Response */
static int
cigi4_add_sensor_extended_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_view_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_sensor_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_sensor_status, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_entity_id_valid, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_gate_x_size, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_gate_y_size, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_gate_x_pos, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_gate_y_pos, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_frame_ctr, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_track_lat, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_track_lon, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_sensor_extended_response_track_alt, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Position Response */
static int
cigi3_add_position_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_position_response_object_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_position_response_part_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_position_response_object_class, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_position_response_coord_system, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_position_response_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_position_response_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_position_response_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_position_response_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_position_response_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_position_response_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Position Response */
static int
cigi4_add_position_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_position_response_part_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_position_response_object_class, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(tree, hf_cigi3_position_response_coord_system, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_position_response_object_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_position_response_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_position_response_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_position_response_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_position_response_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_position_response_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_position_response_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Weather Conditions Response */
static int
cigi3_add_weather_conditions_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_request_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_humidity, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_air_temp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_visibility_range, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_horiz_speed, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_vert_speed, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_wind_direction, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_barometric_pressure, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Weather Conditions Response */
static int
cigi4_add_weather_conditions_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_request_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_humidity, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_air_temp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_visibility_range, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_horiz_speed, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_vert_speed, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_wind_direction, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_weather_conditions_response_barometric_pressure, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI3 Aerosol Concentration Response */
static int
cigi3_add_aerosol_concentration_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_aerosol_concentration_response_request_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_aerosol_concentration_response_layer_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_aerosol_concentration_response_aerosol_concentration, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Aerosol Concentration Response */
static int
cigi4_add_aerosol_concentration_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_aerosol_concentration_response_request_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_aerosol_concentration_response_layer_id, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_aerosol_concentration_response_aerosol_concentration, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Maritime Surface Conditions Response */
static int
cigi3_add_maritime_surface_conditions_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_response_request_id, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_response_sea_surface_height, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_response_surface_water_temp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_response_surface_clarity, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Maritime Surface Conditions Response */
static int
cigi4_add_maritime_surface_conditions_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_response_request_id, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_response_sea_surface_height, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_response_surface_water_temp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_maritime_surface_conditions_response_surface_clarity, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Terrestrial Surface Conditions Response */
static int
cigi3_add_terrestrial_surface_conditions_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_response_request_id, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_response_surface_id, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Terrestrial Surface Conditions Response */
static int
cigi4_add_terrestrial_surface_conditions_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_response_request_id, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_terrestrial_surface_conditions_response_surface_id, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Collision Detection Segment Notification */
static int
cigi3_add_collision_detection_segment_notification(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_segment_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_type, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_contacted_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_material_code, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_intersection_distance, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Collision Detection Segment Notification */
static int
cigi4_add_collision_detection_segment_notification(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_contacted_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_segment_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_type, tvb, offset, 1, cigi_byte_order);
    offset += 3;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_material_code, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_segment_notification_intersection_distance, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Collision Detection Volume Notification */
static int
cigi3_add_collision_detection_volume_notification(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_notification_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_notification_volume_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_notification_type, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_notification_contacted_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_notification_contacted_volume_id, tvb, offset, 1, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Collision Detection Volume Notification */
static int
cigi4_add_collision_detection_volume_notification(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_notification_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_notification_contacted_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_notification_volume_id, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_notification_type, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_collision_detection_volume_notification_contacted_volume_id, tvb, offset, 1, cigi_byte_order);
    offset += 6;

    return offset;
}

/* CIGI3 Animation Stop Notification */
static int
cigi3_add_animation_stop_notification(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_animation_stop_notification_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 6;

    return offset;
}

/* CIGI4 Animation Stop Notification */
static int
cigi4_add_animation_stop_notification(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_animation_stop_notification_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI3 Event Notification */
static int
cigi3_add_event_notification(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_event_notification_event_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_event_notification_data_1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_event_notification_data_2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_event_notification_data_3, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI4 Event Notification */
static int
cigi4_add_event_notification(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_event_notification_event_id, tvb, offset, 2, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_event_notification_data_1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_event_notification_data_2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_event_notification_data_3, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI3 Image Generator Message */
static int
cigi3_add_image_generator_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_image_generator_message_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    if (tvb_reported_length_remaining(tvb, offset) < 2) {
        proto_tree_add_expert_format(tree, pinfo, &ei_cigi_invalid_len, tvb, 0,
            tvb_reported_length(tvb), "Insufficient room for image generator message");
    } else {
        proto_tree_add_item(tree, hf_cigi3_image_generator_message_message, tvb,
            offset, tvb_reported_length_remaining(tvb, offset), cigi_byte_order);
    }

    return (int)tvb_reported_length(tvb);
}

/* CIGI4 Image Generator Message */
static int
cigi4_add_image_generator_message(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_image_generator_message_id, tvb, offset, 2, cigi_byte_order);
    // 2 bytes Reserved (padding to multiple of 4)
    offset += 4;

    if (tvb_reported_length_remaining(tvb, offset) < 2) {
        proto_tree_add_expert_format(tree, pinfo, &ei_cigi_invalid_len, tvb, 0,
            tvb_reported_length(tvb), "Insufficient room for image generator message");
    } else {
        proto_tree_add_item(tree, hf_cigi3_image_generator_message_message, tvb,
            offset, tvb_reported_length_remaining(tvb, offset), cigi_byte_order);
    }

    return (int)tvb_reported_length(tvb);
}

/* Create the tree for CIGI 4 */
static void
cigi4_add_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cigi_tree)
{
    int offset = 0;
    int length = 0;
    int init_offset = 0;

    int packet_id = 0;
    int packet_size = 0;
    int packet_length = 0;
    uint16_t byte_swap = 0;

    proto_tree* cigi_packet_tree = NULL;
    proto_item* tipacket, *ti;
    tvbuff_t* next_tvb;
    int hf_cigi4_packet;

    length = tvb_reported_length(tvb);

    /* Each iteration through this loop is meant to be a separate cigi packet
     * therefore it is okay to assume that at the top of this look we are given
     * a new packet to dissect. */
    while ( offset < length ) {

        byte_swap = tvb_get_ntohs(tvb, offset);
        /* If we have the SOF or IG Control packet set the byte order */
        //if ((packet_id == CIGI4_PACKET_ID_IG_CONTROL || packet_id == CIGI4_PACKET_ID_START_OF_FRAME) && global_cigi_byte_order == CIGI_BYTE_ORDER_FROM_PACKET) {
            //If the parser detects a zero in the "leftmost" byte, then the message is in Big Endian byte
            if ((byte_swap & 0xFF00) == 0) {
                cigi_byte_order = ENC_BIG_ENDIAN;
            }
            else {
                cigi_byte_order = ENC_LITTLE_ENDIAN;
            }
        //}
        packet_id = tvb_get_uint16(tvb, offset + 2, cigi_byte_order);
        packet_size = tvb_get_uint16(tvb, offset, cigi_byte_order);

        /* If we have the start of frame or IG Control packet set the version */
        if ( ( packet_id == CIGI4_PACKET_ID_IG_CONTROL || packet_id == CIGI4_PACKET_ID_START_OF_FRAME ) && global_cigi_version == CIGI_VERSION_FROM_PACKET ) {
            cigi_version = tvb_get_uint8(tvb, 4);

            if (( packet_size == CIGI4_PACKET_SIZE_IG_CONTROL && packet_id == CIGI4_PACKET_ID_IG_CONTROL ) ||
                ( packet_size == CIGI4_PACKET_SIZE_START_OF_FRAME && packet_id == CIGI4_PACKET_ID_START_OF_FRAME )) {
               cigi_minor_version = tvb_get_uint8(tvb, 7) >> 4;
            } else {
               cigi_minor_version = 0;
            }
        }

        /* Add the subtree for the packet */
        if ( packet_id == CIGI4_PACKET_ID_IG_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_ig_control;
            packet_length = CIGI4_PACKET_SIZE_IG_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_ENTITY_POSITION ) {
            hf_cigi4_packet = hf_cigi4_entity_position;
            packet_length = CIGI4_PACKET_SIZE_ENTITY_POSITION;
        } else if ( packet_id == CIGI4_PACKET_ID_CONFORMAL_CLAMPED_ENTITY_POSITION ) {
            hf_cigi4_packet = hf_cigi4_conformal_clamped_entity_position;
            packet_length = CIGI4_PACKET_SIZE_CONFORMAL_CLAMPED_ENTITY_POSITION;
        } else if ( packet_id == CIGI4_PACKET_ID_COMPONENT_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_component_control;
            packet_length = CIGI4_PACKET_SIZE_COMPONENT_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_SHORT_COMPONENT_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_short_component_control;
            packet_length = CIGI4_PACKET_SIZE_SHORT_COMPONENT_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_ARTICULATED_PART_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_articulated_part_control;
            packet_length = CIGI4_PACKET_SIZE_ARTICULATED_PART_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_SHORT_ARTICULATED_PART_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_short_articulated_part_control;
            packet_length = CIGI4_PACKET_SIZE_SHORT_ARTICULATED_PART_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_VELOCITY_CONTROL ) {
            hf_cigi4_packet = hf_cigi4_velocity_control;
            packet_length = CIGI4_PACKET_SIZE_VELOCITY_CONTROL;
        }  else if ( packet_id == CIGI4_PACKET_ID_CELESTIAL_SPHERE_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_celestial_sphere_control;
            packet_length = CIGI4_PACKET_SIZE_CELESTIAL_SPHERE_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_ATMOSPHERE_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_atmosphere_control;
            packet_length = CIGI4_PACKET_SIZE_ATMOSPHERE_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_ENVIRONMENTAL_REGION_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_environmental_region_control;
            packet_length = CIGI4_PACKET_SIZE_ENVIRONMENTAL_REGION_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_WEATHER_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_weather_control;
            packet_length = CIGI4_PACKET_SIZE_WEATHER_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_MARITIME_SURFACE_CONDITIONS_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_maritime_surface_conditions_control;
            packet_length = CIGI4_PACKET_SIZE_MARITIME_SURFACE_CONDITIONS_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_WAVE_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_wave_control;
            packet_length = CIGI4_PACKET_SIZE_WAVE_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_terrestrial_surface_conditions_control;
            packet_length = CIGI4_PACKET_SIZE_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_VIEW_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_view_control;
            packet_length = CIGI4_PACKET_SIZE_VIEW_CONTROL;
        } else if (packet_id == CIGI4_PACKET_ID_SENSOR_CONTROL) {
            hf_cigi4_packet = hf_cigi3_sensor_control;
            packet_length = CIGI4_PACKET_SIZE_SENSOR_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_MOTION_TRACKER_CONTROL ) {
            hf_cigi4_packet = hf_cigi3_motion_tracker_control;
            packet_length = CIGI4_PACKET_SIZE_MOTION_TRACKER_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_EARTH_REFERENCE_MODEL_DEFINITION ) {
            hf_cigi4_packet = hf_cigi3_earth_reference_model_definition;
            packet_length = CIGI4_PACKET_SIZE_EARTH_REFERENCE_MODEL_DEFINITION;
        } else if ( packet_id == CIGI4_PACKET_ID_ACCELERATION_CONTROL ) {
            hf_cigi4_packet = hf_cigi4_acceleration_control;
            packet_length = CIGI4_PACKET_SIZE_ACCELERATION_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_VIEW_DEFINITION ) {
            hf_cigi4_packet = hf_cigi3_view_definition;
            packet_length = CIGI4_PACKET_SIZE_VIEW_DEFINITION;
        } else if ( packet_id == CIGI4_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION ) {
            hf_cigi4_packet = hf_cigi3_collision_detection_segment_definition;
            packet_length = CIGI4_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_DEFINITION;
        } else if ( packet_id == CIGI4_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION ) {
            hf_cigi4_packet = hf_cigi3_collision_detection_volume_definition;
            packet_length = CIGI4_PACKET_SIZE_COLLISION_DETECTION_VOLUME_DEFINITION;
        } else if ( packet_id == CIGI4_PACKET_ID_HAT_HOT_REQUEST ) {
            hf_cigi4_packet = hf_cigi3_hat_hot_request;
            packet_length = CIGI4_PACKET_SIZE_HAT_HOT_REQUEST;
        } else if ( packet_id == CIGI4_PACKET_ID_LINE_OF_SIGHT_SEGMENT_REQUEST ) {
            hf_cigi4_packet = hf_cigi3_line_of_sight_segment_request;
            packet_length = CIGI4_PACKET_SIZE_LINE_OF_SIGHT_SEGMENT_REQUEST;
        } else if ( packet_id == CIGI4_PACKET_ID_LINE_OF_SIGHT_VECTOR_REQUEST ) {
            hf_cigi4_packet = hf_cigi3_line_of_sight_vector_request;
            packet_length = CIGI4_PACKET_SIZE_LINE_OF_SIGHT_VECTOR_REQUEST;
        } else if ( packet_id == CIGI4_PACKET_ID_POSITION_REQUEST ) {
            hf_cigi4_packet = hf_cigi3_position_request;
            packet_length = CIGI4_PACKET_SIZE_POSITION_REQUEST;
        } else if ( packet_id == CIGI4_PACKET_ID_ENVIRONMENTAL_CONDITIONS_REQUEST ) {
            hf_cigi4_packet = hf_cigi3_environmental_conditions_request;
            packet_length = CIGI4_PACKET_SIZE_ENVIRONMENTAL_CONDITIONS_REQUEST;
        } else if ( packet_id == CIGI4_PACKET_ID_SYMBOL_SURFACE_DEFINITION ) {
            hf_cigi4_packet = hf_cigi3_3_symbol_surface_definition;
            packet_length = CIGI4_PACKET_SIZE_SYMBOL_SURFACE_DEFINITION;
        } else if ( packet_id == CIGI4_PACKET_ID_SYMBOL_TEXT_DEFINITION ){
            hf_cigi4_packet = hf_cigi3_3_symbol_text_definition;
            packet_length = packet_size;
        } else if ( packet_id == CIGI4_PACKET_ID_SYMBOL_CIRCLE_DEFINITION ){
            hf_cigi4_packet = hf_cigi3_3_symbol_circle_definition;
            packet_length = packet_size;
        } else if ( packet_id == CIGI4_PACKET_ID_SYMBOL_POLYGON_DEFINITION){
            hf_cigi4_packet = hf_cigi4_symbol_polygon_definition;
            packet_length = packet_size;
        } else if (packet_id == CIGI4_PACKET_ID_SYMBOL_CLONE) {
            hf_cigi4_packet = hf_cigi3_3_symbol_clone;
            packet_length = CIGI4_PACKET_SIZE_SYMBOL_CLONE;
        } else if (packet_id == CIGI4_PACKET_ID_SYMBOL_CONTROL) {
            hf_cigi4_packet = hf_cigi3_3_symbol_control;
            packet_length = CIGI4_PACKET_SIZE_SYMBOL_CONTROL;
        } else if (packet_id == CIGI4_PACKET_ID_SHORT_SYMBOL_CONTROL) {
            hf_cigi4_packet = hf_cigi3_3_short_symbol_control;
            packet_length = CIGI4_PACKET_SIZE_SHORT_SYMBOL_CONTROL;
        } else if (packet_id == CIGI4_PACKET_ID_SYMBOL_CIRCLE_TEXTURED_DEFINITION) {
            hf_cigi4_packet = hf_cigi4_symbol_circle_textured_definition;
            packet_length = packet_size;
        } else if (packet_id == CIGI4_PACKET_ID_SYMBOL_POLYGON_TEXTURED_DEFINITION) {
            hf_cigi4_packet = hf_cigi4_symbol_polygon_textured_definition;
            packet_length = packet_size;
        } else if (packet_id == CIGI4_PACKET_ID_ENTITY_CONTROL) {
            hf_cigi4_packet = hf_cigi4_entity_control;
            packet_length = CIGI4_PACKET_SIZE_ENTITY_CONTROL;
        }else if (packet_id == CIGI4_PACKET_ID_ANIMATION_CONTROL) {
            hf_cigi4_packet = hf_cigi4_animation_control;
            packet_length = CIGI4_PACKET_SIZE_ANIMATION_CONTROL;
        } else if ( packet_id == CIGI4_PACKET_ID_START_OF_FRAME ) {
            hf_cigi4_packet = hf_cigi4_start_of_frame;
            packet_length = CIGI4_PACKET_SIZE_START_OF_FRAME;
        } else if ( packet_id == CIGI4_PACKET_ID_HAT_HOT_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_hat_hot_response;
            packet_length = CIGI4_PACKET_SIZE_HAT_HOT_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_HAT_HOT_EXTENDED_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_hat_hot_extended_response;
            packet_length = CIGI4_PACKET_SIZE_HAT_HOT_EXTENDED_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_LINE_OF_SIGHT_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_line_of_sight_response;
            packet_length = CIGI4_PACKET_SIZE_LINE_OF_SIGHT_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_LINE_OF_SIGHT_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_line_of_sight_response;
            packet_length = CIGI4_PACKET_SIZE_LINE_OF_SIGHT_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_LINE_OF_SIGHT_EXTENDED_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_line_of_sight_extended_response;
            packet_length = CIGI4_PACKET_SIZE_LINE_OF_SIGHT_EXTENDED_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_SENSOR_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_sensor_response;
            packet_length = CIGI4_PACKET_SIZE_SENSOR_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_SENSOR_EXTENDED_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_sensor_extended_response;
            packet_length = CIGI4_PACKET_SIZE_SENSOR_EXTENDED_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_POSITION_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_position_response;
            packet_length = CIGI4_PACKET_SIZE_POSITION_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_WEATHER_CONDITIONS_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_weather_conditions_response;
            packet_length = CIGI4_PACKET_SIZE_WEATHER_CONDITIONS_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_AEROSOL_CONCENTRATION_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_aerosol_concentration_response;
            packet_length = CIGI4_PACKET_SIZE_AEROSOL_CONCENTRATION_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_MARITIME_SURFACE_CONDITIONS_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_maritime_surface_conditions_response;
            packet_length = CIGI4_PACKET_SIZE_MARITIME_SURFACE_CONDITIONS_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE ) {
            hf_cigi4_packet = hf_cigi3_terrestrial_surface_conditions_response;
            packet_length = CIGI4_PACKET_SIZE_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE;
        } else if ( packet_id == CIGI4_PACKET_ID_COLLISION_DETECTION_SEGMENT_NOTIFICATION ) {
            hf_cigi4_packet = hf_cigi3_collision_detection_segment_notification;
            packet_length = CIGI4_PACKET_SIZE_COLLISION_DETECTION_SEGMENT_NOTIFICATION;
        } else if ( packet_id == CIGI4_PACKET_ID_COLLISION_DETECTION_VOLUME_NOTIFICATION ) {
            hf_cigi4_packet = hf_cigi3_collision_detection_volume_notification;
            packet_length = CIGI4_PACKET_SIZE_COLLISION_DETECTION_VOLUME_NOTIFICATION;
        } else if ( packet_id == CIGI4_PACKET_ID_ANIMATION_STOP_NOTIFICATION ) {
            hf_cigi4_packet = hf_cigi3_animation_stop_notification;
            packet_length = CIGI4_PACKET_SIZE_ANIMATION_STOP_NOTIFICATION;
        } else if ( packet_id == CIGI4_PACKET_ID_EVENT_NOTIFICATION ) {
            hf_cigi4_packet = hf_cigi3_event_notification;
            packet_length = CIGI4_PACKET_SIZE_EVENT_NOTIFICATION;
        } else if ( packet_id == CIGI4_PACKET_ID_IMAGE_GENERATOR_MESSAGE ) {
            hf_cigi4_packet = hf_cigi3_image_generator_message;
            packet_length = packet_size;
        } else if ( packet_id >= CIGI4_PACKET_ID_LOCALLY_DEFINED_MIN && packet_id <=  CIGI4_PACKET_ID_LOCALLY_DEFINED_MAX) {
            hf_cigi4_packet = hf_cigi4_locally_defined;
            packet_length = packet_size;
        } else if ( packet_id >= CIGI4_PACKET_ID_REGISTERED_MIN && packet_id <= CIGI4_PACKET_ID_REGISTERED_MAX) {
            hf_cigi4_packet = hf_cigi4_registered;
            packet_length = packet_size;
        } else {
            hf_cigi4_packet = hf_cigi_unknown;
            packet_length = packet_size;
        }
        tipacket = proto_tree_add_none_format(cigi_tree, hf_cigi4_packet, tvb, offset, packet_length,
                                              "%s (%i bytes)",
                                              val_to_str_ext_const(packet_id, &cigi4_packet_id_vals_ext, "Unknown"),
                                              packet_length);

        cigi_packet_tree = proto_item_add_subtree(tipacket, ett_cigi);

        /* CIGI4 versions the first word the size of the packet (in bytes).
         * The second word is of a packet is the packet ID. */
        init_offset = offset;
        ti = proto_tree_add_item(cigi_packet_tree, hf_cigi4_packet_size, tvb, offset, 2, cigi_byte_order);
        if (packet_size < 4) {
            expert_add_info(pinfo, ti, &ei_cigi_invalid_len);
            break;
        }
        offset += 2;

        proto_tree_add_item(cigi_packet_tree, hf_cigi4_packet_id, tvb, offset, 2, cigi_byte_order);
        offset += 2;
        /* If packet_size != packet_len for the fixed size packet IDs, attempt
         * to dissect normally then add an expert info and abort afterwards below. */
        next_tvb = tvb_new_subset_length(tvb, offset, packet_length - 4);

        int dissected = dissector_try_uint_new(cigi4_packet_id_table, packet_id,
            next_tvb, pinfo, cigi_packet_tree, false, NULL);

        if (dissected == 0) {
            dissected = cigi_add_data(next_tvb, cigi_packet_tree, 0);
        }

        offset += dissected;

        if (offset-init_offset != packet_length) {
            proto_tree_add_expert(cigi_packet_tree, pinfo, &ei_cigi_invalid_len, tvb, init_offset, offset-init_offset);
            break;
        }
    }
}

/* CIGI4 IG Control */
static int
cigi4_add_ig_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree* field_tree;
    proto_item* tf;

    proto_tree_add_item(tree, hf_cigi_version, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_ig_control_db_number, tvb, offset, 1, cigi_byte_order);
    offset++;

    tf = proto_tree_add_item(tree, hf_cigi4_ig_control_entity_substitution, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_ig_control_entity_substitution);
    proto_tree_add_item(field_tree, hf_cigi4_ig_control_entity_substitution_enable, tvb, offset, 1, cigi_byte_order);
    offset++;

    tf = proto_tree_add_item(tree, hf_cigi4_ig_control_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_ig_control_flags);
    proto_tree_add_item(field_tree, hf_cigi3_ig_control_ig_mode, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_ig_control_timestamp_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi4_ig_control_smoothing_enable, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_2_ig_control_minor_version, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_2_ig_control_host_frame_number, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_2_ig_control_last_ig_frame_number, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_ig_control_timestamp, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Start of Frame */
static int
cigi4_add_start_of_frame(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    int offset = 0;

    proto_tree_add_item(tree, hf_cigi_version, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_start_of_frame_db_number, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    tf = proto_tree_add_item(tree, hf_cigi4_start_of_frame_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_start_of_frame_flags);

    proto_tree_add_item(field_tree, hf_cigi4_start_of_frame_ig_mode, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi4_start_of_frame_timestamp_valid, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi4_start_of_frame_earth_reference_model, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi4_start_of_frame_minor_version, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi4_start_of_frame_ig_frame_number, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_start_of_frame_timestamp, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_start_of_frame_last_host_frame_number, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    tf = proto_tree_add_item(tree, hf_cigi4_start_of_frame_ig_condition_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_start_of_frame_ig_condition_flags);
    proto_tree_add_item(field_tree, hf_cigi4_start_of_frame_condition_overframing, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi4_start_of_frame_condition_paging, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi4_start_of_frame_condition_excessive_variable_length_data, tvb, offset, 1, cigi_byte_order);
    offset += 4;

    return offset;
}

/* CIGI Entity Position */
static int
cigi4_add_entity_position(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree* field_tree;
    proto_item* tf;

    tf = proto_tree_add_item(tree, hf_cigi4_entity_position_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_entity_position_flags);
    proto_tree_add_item(field_tree, hf_cigi4_entity_position_attach_state, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi4_entity_position_ground_ocean_clamp, tvb, offset, 1, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_entity_position_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi4_entity_position_parent_id, tvb, offset, 2, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_entity_position_roll, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_entity_position_pitch, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_entity_position_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_entity_position_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi4_entity_position_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi4_entity_position_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}


/* CIGI Conformal Clamped Entity Position */
static int
cigi4_add_conformal_clamped_entity_position(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_) {
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi4_conformal_clamped_entity_position_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi4_conformal_clamped_entity_position_yaw, tvb, offset, 4, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi4_conformal_clamped_entity_position_lat, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi4_conformal_clamped_entity_position_lon, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}

/* CIGI4 Component Control */
static int
cigi4_add_component_control(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_cigi3_component_control_component_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_3_component_control_component_class, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_component_control_component_state, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_component_control_instance_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    //reserved
    offset += 6;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_1, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_2, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_3, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_4, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_5, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    proto_tree_add_item(tree, hf_cigi3_component_control_data_6, tvb, offset, 4, cigi_byte_order);
    offset += 4;

    return offset;
}


/* CIGI4 HAT/HOT Request */
static int
cigi4_add_hat_hot_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree* field_tree;
    proto_item* tf;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_hat_hot_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_entity_id, tvb, offset, 2, cigi_byte_order);
    offset += 2;

    //subtree
    tf = proto_tree_add_item(tree, hf_cigi4_hat_hot_request_flags, tvb, offset, 1, cigi_byte_order);
    field_tree = proto_item_add_subtree(tf, ett_cigi4_hat_hot_request_flags);
    proto_tree_add_item(field_tree, hf_cigi3_hat_hot_request_type, tvb, offset, 1, cigi_byte_order);
    proto_tree_add_item(field_tree, hf_cigi3_hat_hot_request_coordinate_system, tvb, offset, 1, cigi_byte_order);
    offset++;

    proto_tree_add_item(tree, hf_cigi3_2_hat_hot_request_update_period, tvb, offset, 1, cigi_byte_order);
    offset++;

    //reserved
    offset += 6;


    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_lat_xoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_lon_yoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    proto_tree_add_item(tree, hf_cigi3_hat_hot_request_alt_zoff, tvb, offset, 8, cigi_byte_order);
    offset += 8;

    return offset;
}



/* Register the protocol with Wireshark */
void
proto_register_cigi(void)
{
    module_t *cigi_module;
    expert_module_t* expert_cigi;

    static hf_register_info hf[] = {
        /* All Versions of CIGI */
        { &hf_cigi_src_port,
            { "Source Port", "cigi.srcport",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi_dest_port,
            { "Destination Port", "cigi.destport",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi_port,
            { "Source or Destination Port", "cigi.port",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi_data,
            { "Data", "cigi.data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_cigi_frame_size,
            { "Frame Size (bytes)", "cigi.frame_size",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of bytes sent with all cigi packets in this frame", HFILL }
        },

        { &hf_cigi_packet_id,
            { "Packet ID", "cigi.packet_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the packet's id", HFILL }
        },
        { &hf_cigi_packet_size,
            { "Packet Size (bytes)", "cigi.packet_size",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the number of bytes in this type of packet", HFILL }
        },
        { &hf_cigi_version,
            { "CIGI Version", "cigi.version",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the version of CIGI interface that is currently running on the host", HFILL }
        },

        { &hf_cigi_unknown,
            { "Unknown", "cigi.unknown",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Unknown Packet", HFILL }
        },

        /* CIGI2 */
        { &hf_cigi2_packet_id,
            { "Packet ID", "cigi.packet_id",
                FT_UINT8, BASE_DEC|BASE_EXT_STRING, &cigi2_packet_id_vals_ext, 0x0,
                "Identifies the packet's ID", HFILL }
        },

        /* CIGI3 */
        { &hf_cigi3_packet_id,
            { "Packet ID", "cigi.packet_id",
                FT_UINT8, BASE_DEC|BASE_EXT_STRING, &cigi3_packet_id_vals_ext, 0x0,
                "Identifies the packet's ID", HFILL }
        },
        { &hf_cigi3_byte_swap,
            { "Byte Swap", "cigi.byte_swap",
                FT_UINT16, BASE_HEX, VALS(cigi3_byte_swap_vals), 0x0,
                "Used to determine whether the incoming data should be byte-swapped", HFILL }
        },

        /* CIGI4 */
        { &hf_cigi4_packet_id,
            { "Packet ID", "cigi.packet_id",
                FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cigi4_packet_id_vals_ext, 0x0,
                "Identifies the packet's ID", HFILL }
        },
        { &hf_cigi4_packet_size,
            { "Packet Size", "cigi.packet_size",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the number of bytes in this type of packet", HFILL }
        },

        /* CIGI2 IG Control */
        { &hf_cigi2_ig_control,
            { "IG Control", "cigi.ig_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "IG Control Packet", HFILL }
        },
        { &hf_cigi2_ig_control_db_number,
            { "Database Number", "cigi.ig_control.db_number",
                FT_INT8, BASE_DEC, NULL, 0x0,
                "Identifies the number associated with the database requiring loading", HFILL }
        },
        { &hf_cigi2_ig_control_ig_mode,
            { "IG Mode Change Request", "cigi.ig_control.ig_mode",
                FT_UINT8, BASE_DEC, VALS(cigi2_ig_control_ig_mode_vals), 0xc0,
                "Commands the IG to enter its various modes", HFILL }
        },
        { &hf_cigi2_ig_control_tracking_enable,
            { "Tracking Device Enable", "cigi.ig_control.tracking_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
                "Identifies the state of an external tracking device", HFILL }
        },
        { &hf_cigi2_ig_control_boresight,
            { "Tracking Device Boresight", "cigi.ig_control.boresight",
                FT_BOOLEAN, 8, NULL, 0x10,
                "Used by the host to enable boresight mode", HFILL }
        },
        { &hf_cigi2_ig_control_frame_ctr,
            { "Frame Counter", "cigi.ig_control.frame_ctr",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Identifies a particular frame", HFILL }
        },
        { &hf_cigi2_ig_control_time_tag,
            { "Timing Value (microseconds)", "cigi.ig_control.time_tag",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies synchronous operation", HFILL }
        },

        /* CIGI3 IG Control */
        { &hf_cigi3_ig_control,
            { "IG Control", "cigi.ig_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "IG Control Packet", HFILL }
        },
        { &hf_cigi3_ig_control_db_number,
            { "Database Number", "cigi.ig_control.db_number",
                FT_INT8, BASE_DEC, NULL, 0x0,
                "Used to initiate a database load on the IG", HFILL }
        },
        { &hf_cigi3_ig_control_ig_mode,
            { "IG Mode", "cigi.ig_control.ig_mode",
                FT_UINT8, BASE_DEC, VALS(cigi3_ig_control_ig_mode_vals), 0x03,
                "Dictates the IG's operational mode", HFILL }
        },
        { &hf_cigi3_ig_control_timestamp_valid,
            { "Timestamp Valid", "cigi.ig_control.timestamp_valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x04,
                "Indicates whether the timestamp contains a valid value", HFILL }
        },
        { &hf_cigi3_ig_control_frame_ctr,
            { "Frame Counter", "cigi.ig_control.frame_ctr",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Contains a number that identifying the frame", HFILL }
        },
        { &hf_cigi3_ig_control_timestamp,
            { "Timestamp (microseconds)", "cigi.ig_control.timestamp",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Indicates the number of 10 microsecond \"ticks\" since some initial reference time", HFILL }
        },

        /* CIGI3_2 IG Control */
        { &hf_cigi3_2_ig_control_minor_version,
            { "Minor Version", "cigi.ig_control.minor_version",
                FT_UINT8, BASE_DEC, NULL, 0xF0,
                "Indicates the minor version of the CIGI interface", HFILL }
        },
        { &hf_cigi3_2_ig_control_host_frame_number,
            { "Host Frame Number", "cigi.ig_control.host_frame_number",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Uniquely identifies a data frame on the host", HFILL }
        },
        { &hf_cigi3_2_ig_control_last_ig_frame_number,
            { "IG Frame Number", "cigi.ig_control.last_ig_frame_number",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Contains the value of the IG Frame Number parameter in the last Start of Frame packet received from the IG", HFILL }
        },

        /* CIGI3_3 IG Control */
        { &hf_cigi3_3_ig_control_extrapolation_enable,
            { "Extrapolation/Interpolation Enable", "cigi.ig_control.extrapolation_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Indicates whether any dead reckoning is enabled.", HFILL }
        },

        /* CIGI4 IG Control */
        { &hf_cigi4_ig_control_entity_substitution,
            { "Substitution", "cigi.ig_control.substitution",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi4_ig_control_entity_substitution_enable,
            { "Substitution Enable", "cigi.ig_control.substitution_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Sets this parameter to Enable (1) the IG to substitute of entity types for all entities.", HFILL }
        },
        { &hf_cigi4_ig_control_flags,
            { "Flags", "cigi.ig_control.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi4_ig_control_smoothing_enable,
            { "Smoothing Enable", "cigi.ig_control.smoothing_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Indicates whether any dead reckoning is enabled.", HFILL }
        },

        /* CIGI4 Entity Position */
        { &hf_cigi4_entity_position,
            { "Entity Position", "cigi.entity_position",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Entity Position Packet", HFILL }
        },
        { &hf_cigi4_entity_position_entity_id,
            { "Entity ID", "cigi.entity_position.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which this packet is applied", HFILL }
        },
        { &hf_cigi4_entity_position_flags,
            { "Flags", "cigi.entity_position.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi4_entity_position_attach_state,
            { "Attach State", "cigi.entity_position.attach_state",
                FT_BOOLEAN, 8, TFS(&attach_detach_tfs), 0x01,
                "Identifies whether the entity should be attach as a child to a parent", HFILL }
        },
        { &hf_cigi4_entity_position_ground_ocean_clamp,
            { "Ground/Ocean Clamp", "cigi.entity_position.ground_ocean_clamp",
                FT_UINT8, BASE_DEC, VALS(cigi4_entity_control_ground_ocean_clamp_vals), 0x06,
                "Specifies whether the entity should be clamped to the ground or water surface", HFILL }
        },
        { &hf_cigi4_entity_position_parent_id,
            { "Parent ID", "cigi.entity_position.parent_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the parent for the entity", HFILL }
        },
        { &hf_cigi4_entity_position_roll,
            { "Roll (degrees)", "cigi.entity_position.roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the roll angle of the entity", HFILL }
        },
        { &hf_cigi4_entity_position_pitch,
            { "Pitch (degrees)", "cigi.entity_position.pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the pitch angle of the entity", HFILL }
        },
        { &hf_cigi4_entity_position_yaw,
            { "Yaw (degrees)", "cigi.entity_position.yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the instantaneous heading of the entity", HFILL }
        },
        { &hf_cigi4_entity_position_lat_xoff,
            { "Latitude (degrees)/X Offset (m)", "cigi.entity_position.lat_xoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the entity's geodetic latitude or the distance from the parent's reference point along its parent's X axis", HFILL }
        },
        { &hf_cigi4_entity_position_lon_yoff,
            { "Longitude (degrees)/Y Offset (m)", "cigi.entity_position.lon_yoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the entity's geodetic longitude or the distance from the parent's reference point along its parent's Y axis", HFILL }
        },
        { &hf_cigi4_entity_position_alt_zoff,
            { "Altitude (m)/Z Offset (m)", "cigi.entity_position.alt_zoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the entity's altitude or the distance from the parent's reference point along its parent's Z axis", HFILL }
        },

        /* CIGI2 Entity Control */
        { &hf_cigi2_entity_control,
            { "Entity Control", "cigi.entity_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Entity Control Packet", HFILL }
        },
        { &hf_cigi2_entity_control_entity_id,
            { "Entity ID", "cigi.entity_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the entity motion system", HFILL }
        },
        { &hf_cigi2_entity_control_entity_state,
            { "Entity State", "cigi.entity_control.entity_state",
                FT_UINT8, BASE_DEC, VALS(cigi2_entity_control_entity_state_vals), 0xc0,
                "Identifies the entity's geometry state", HFILL }
        },
        { &hf_cigi2_entity_control_attach_state,
            { "Attach State", "cigi.entity_control.attach_state",
                FT_BOOLEAN, 8, TFS(&attach_detach_tfs), 0x20,
                "Identifies whether the entity should be attach as a child to a parent", HFILL }
        },
        { &hf_cigi2_entity_control_collision_detect,
            { "Collision Detection Request", "cigi.entity_control.collision_detect",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Identifies if collision detection is enabled for the entity", HFILL }
        },
        { &hf_cigi2_entity_control_effect_state,
            { "Effect Animation State", "cigi.entity_control.effect_state",
                FT_UINT8, BASE_DEC, VALS(cigi2_entity_control_effect_state_vals), 0x0c,
                "Identifies the animation state of a special effect", HFILL }
        },
        { &hf_cigi2_entity_control_type,
            { "Entity Type", "cigi.entity_control.type",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the type of the entity", HFILL }
        },
        { &hf_cigi2_entity_control_parent_id,
            { "Parent Entity ID", "cigi.entity_control.parent_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the parent to which the entity should be attached", HFILL }
        },
        { &hf_cigi2_entity_control_opacity,
            { "Percent Opacity", "cigi.entity_control.opacity",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the degree of opacity of the entity", HFILL }
        },
        { &hf_cigi2_entity_control_internal_temp,
            { "Internal Temperature (degrees C)", "cigi.entity_control.internal_temp",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the internal temperature of the entity in degrees Celsius", HFILL }
        },
        { &hf_cigi2_entity_control_roll,
            { "Roll (degrees)", "cigi.entity_control.roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the roll angle of the entity in degrees", HFILL }
        },
        { &hf_cigi2_entity_control_pitch,
            { "Pitch (degrees)", "cigi.entity_control_pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the pitch of the entity in degrees", HFILL }
        },
        { &hf_cigi2_entity_control_heading,
            { "Heading (degrees)", "cigi.entity_control_heading",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the heading of the entity in degrees", HFILL }
        },
        { &hf_cigi2_entity_control_alt,
            { "Altitude (m)", "cigi.entity_control.alt",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Identifies the altitude position of the reference point of the entity in meters", HFILL }
        },
        { &hf_cigi2_entity_control_lat,
            { "Latitude (degrees)", "cigi.entity_control.lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Identifies the latitude position of the reference point of the entity in degrees", HFILL }
        },
        { &hf_cigi2_entity_control_lon,
            { "Longitude (degrees)", "cigi.entity_control.lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Identifies the longitude position of the reference point of the entity in degrees", HFILL }
        },

        /* CIGI3 Entity Control */
        { &hf_cigi3_entity_control,
            { "Entity Control", "cigi.entity_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Entity Control Packet", HFILL }
        },
        { &hf_cigi3_entity_control_entity_id,
            { "Entity ID", "cigi.entity_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which this packet is applied", HFILL }
        },
        { &hf_cigi3_entity_control_entity_state,
            { "Entity State", "cigi.entity_control.entity_state",
                FT_UINT8, BASE_DEC, VALS(cigi3_entity_control_entity_state_vals), 0x03,
                "Specifies whether the entity should be active or destroyed", HFILL }
        },
        { &hf_cigi3_entity_control_attach_state,
            { "Attach State", "cigi.entity_control.attach_state",
                FT_BOOLEAN, 8, TFS(&attach_detach_tfs), 0x04,
                "Specifies whether the entity should be attached as a child to a parent", HFILL }
        },
        { &hf_cigi3_entity_control_collision_detection_request,
            { "Collision Detection Request", "cigi.entity_control.coll_det_request",
                FT_BOOLEAN, 8, TFS(&cigi3_entity_control_collision_detection_request_tfs), 0x08,
                "Determines whether any collision detection segments and volumes associated with this entity are used as the source in collision testing", HFILL }
        },
        { &hf_cigi3_entity_control_inherit_alpha,
            { "Inherit Alpha", "cigi.entity_control.inherit_alpha",
                FT_BOOLEAN, 8, TFS(&inherited_not_inherited_tfs), 0x10,
                "Specifies whether the entity's alpha is combined with the apparent alpha of its parent", HFILL }
        },
        { &hf_cigi3_entity_control_ground_ocean_clamp,
            { "Ground/Ocean Clamp", "cigi.entity_control.ground_ocean_clamp",
                FT_UINT8, BASE_DEC, VALS(cigi3_entity_control_ground_ocean_clamp_vals), 0x60,
                "Specifies whether the entity should be clamped to the ground or water surface", HFILL }
        },
        { &hf_cigi3_entity_control_animation_direction,
            { "Animation Direction", "cigi.entity_control.animation_dir",
                FT_BOOLEAN, 8, TFS(&cigi3_entity_control_animation_direction_tfs), 0x01,
                "Specifies the direction in which an animation plays", HFILL }
        },
        { &hf_cigi3_entity_control_animation_loop_mode,
            { "Animation Loop Mode", "cigi.entity_control.animation_loop_mode",
                FT_BOOLEAN, 8, TFS(&cigi3_entity_control_animation_loop_mode_tfs), 0x02,
                "Specifies whether an animation should be a one-shot", HFILL }
        },
        { &hf_cigi3_entity_control_animation_state,
            { "Animation State", "cigi.entity_control.animation_state",
                FT_UINT8, BASE_DEC, VALS(cigi3_entity_control_animation_state_vals), 0x0c,
                "Specifies the state of an animation", HFILL }
        },
        { &hf_cigi3_entity_control_alpha,
            { "Alpha", "cigi.entity_control.alpha",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the explicit alpha to be applied to the entity's geometry", HFILL }
        },
        { &hf_cigi3_entity_control_entity_type,
            { "Entity Type", "cigi.entity_control.entity_type",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the type for the entity", HFILL }
        },
        { &hf_cigi3_entity_control_parent_id,
            { "Parent ID", "cigi.entity_control.parent_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the parent for the entity", HFILL }
        },
        { &hf_cigi3_entity_control_roll,
            { "Roll (degrees)", "cigi.entity_control.roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the roll angle of the entity", HFILL }
        },
        { &hf_cigi3_entity_control_pitch,
            { "Pitch (degrees)", "cigi.entity_control.pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the pitch angle of the entity", HFILL }
        },
        { &hf_cigi3_entity_control_yaw,
            { "Yaw (degrees)", "cigi.entity_control.yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the instantaneous heading of the entity", HFILL }
        },
        { &hf_cigi3_entity_control_lat_xoff,
            { "Latitude (degrees)/X Offset (m)", "cigi.entity_control.lat_xoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the entity's geodetic latitude or the distance from the parent's reference point along its parent's X axis", HFILL }
        },
        { &hf_cigi3_entity_control_lon_yoff,
            { "Longitude (degrees)/Y Offset (m)", "cigi.entity_control.lon_yoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the entity's geodetic longitude or the distance from the parent's reference point along its parent's Y axis", HFILL }
        },
        { &hf_cigi3_entity_control_alt_zoff,
            { "Altitude (m)/Z Offset (m)", "cigi.entity_control.alt_zoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the entity's altitude or the distance from the parent's reference point along its parent's Z axis", HFILL }
        },

        /* CIGI3_3 Entity Control */
        { &hf_cigi3_3_entity_control_extrapolation_enable,
            { "Linear Extrapolation/Interpolation Enable", "cigi.entity_control.extrapolation_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Indicates whether the entity's motion may be smoothed by extrapolation or interpolation.", HFILL }
        },

        /* CIGI4 Entity Control */
        { &hf_cigi4_entity_control,
            { "Entity Control", "cigi.entity_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Entity Control Packet", HFILL }
        },
        { &hf_cigi4_entity_control_entity_state,
            { "Entity State", "cigi.entity_control.entity_state",
                FT_UINT8, BASE_DEC, VALS(cigi4_entity_control_entity_state_vals), 0x03,
                "Specifies whether the entity should be active or destroyed", HFILL }
        },
        { &hf_cigi4_entity_control_collision_reporting_enable,
            { "Collision Detection Request", "cigi.entity_control.coll_det_request",
                FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled), 0x04,
                "Specifies whether any collision detection segments and volumes associated with this entity are used as the source in collision testing", HFILL }
        },
        { &hf_cigi4_entity_control_inherit_alpha,
            { "Inherit Alpha", "cigi.entity_control.inherit_alpha",
                FT_BOOLEAN, 8, TFS(&cigi4_entity_control_inherit_alpha_tfs), 0x8,
                "Specifies whether the entity's alpha is combined with the apparent alpha of its parent", HFILL }
        },
        { &hf_cigi4_entity_control_smooting_enable,
            { "Smoothing Enable", "cigi.entity_control.smoothing_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Specifies whether the IG shall smooth the entity’s motion by extrapolation or interpolation.", HFILL }
        },
        { &hf_cigi4_entity_control_extended_entity_type,
            { "Linear Extrapolation/Interpolation Enable", "cigi.entity_control.extended_entity_type",
                FT_BOOLEAN, 8, TFS(&tfs_entity_control_extended_entity_type), 0x20,
                "Specifies whether the IG shall use a 16-bit Short Entity Type definition for the Entity ID or an extended 64-bit definition.", HFILL }
        },
        { &hf_cigi4_entity_control_alpha,
            { "Alpha", "cigi.entity_control.alpha",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the explicit alpha to be applied to the entity's geometry", HFILL }
        },
        { &hf_cigi4_entity_control_entity_id,
            { "Entity ID", "cigi.entity_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "This parameter identifies a specific entity", HFILL }
        },
        { &hf_cigi4_entity_control_entity_kind,
            { "Parent Kind", "cigi.entity_control.parent_kind",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "This field shall identify the kind of entity described by the Entity Type record", HFILL }
        },
        { &hf_cigi4_entity_control_entity_domain,
            { "Entity Domain", "cigi.entity_control.entity_domain",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the domain in which the entity operates", HFILL }
        },
        { &hf_cigi4_entity_control_entity_country,
            { "Entity Country", "cigi.entity_control.entity_country",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the roll angle of the entity", HFILL }
        },
        { &hf_cigi4_entity_control_entity_category,
            { "Entity Category", "cigi.entity_control.entity_category",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the instantaneous heading of the entity", HFILL }
        },
        { &hf_cigi4_entity_control_entity_subcategory,
            { "Entity Subcategory", "cigi.entity_control.entity_subcategory",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies a particular subcategory to which an entity belongs based on the Category field", HFILL }
        },
        { &hf_cigi4_entity_control_entity_specific,
            { "Entity Specific", "cigi.entity_control.entity_specific",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies a specific information about an entity based on the Subcategory field", HFILL }
        },
        { &hf_cigi4_entity_control_entity_extra,
            { "Entity Extra", "cigi.entity_control.entity_extra",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies extra information required to describe a particular entity", HFILL }
        },

        /* CIGI4 Animation Control */
        { &hf_cigi4_animation_control,
            { "Animation Control", "cigi.animation_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Animation Control Packet", HFILL }
        },
        { &hf_cigi4_animation_control_state,
            { "Animation State", "cigi.animation_control_state",
                FT_BOOLEAN, 8, TFS(&cigi4_animation_control_state_tfs), 0x01,
                "Specifies the state of an animation.", HFILL }
        },
        { &hf_cigi4_animation_control_frame_position_reset,
            { "Animation State Position Reset", "cigi.animation_control_state_position_reset",
                FT_BOOLEAN, 8, TFS(&cigi4_animation_control_state_positon_reset_tfs), 0x02,
                "whether the animation is restarted from the beginning or just continues from its current frame", HFILL }
        },
        { &hf_cigi4_animation_control_loop_mode,
            { "Animation Loop Mode", "cigi.animation_control_loop_mode",
                FT_BOOLEAN, 8, TFS(&cigi4_animation_control_state_loop_mode), 0x04,
                "Specifies whether an animation should be a one-shot or should loop continuously", HFILL }
        },
        { &hf_cigi4_animation_control_inherit_alpha,
            { "Inherit Alpha", "cigi.animation_control_inherit_alpha",
                FT_BOOLEAN, 8, TFS(&cigi4_animation_control_state_inherit_alpha), 0x04,
                "Specifies whether the animation’s alpha is combined with the apparent alpha of the entity", HFILL }
        },
        { &hf_cigi4_animation_control_alpha,
            { "Alpha", "cigi.animation_control_alpha",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the explicit alpha to be applied to the entity’s geometry", HFILL }
        },
        { &hf_cigi4_animation_control_entity_id,
            { "Entity ID", "cigi.animation_control_entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "This parameter identifies a specific entity", HFILL }
        },
        { &hf_cigi4_animation_control_animation_id,
            { "Animation ID", "cigi.animation_control_animation_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "This parameter identifies the animation to which the data in this packet should be applied", HFILL }
        },
        { &hf_cigi4_animation_control_animation_speed,
            { "Animation Speed", "cigi.animation_control_animation_speed",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "This parameter identifies the animation to which the data in this packet should be applied", HFILL }
        },

        /* CIGI3 Conformal Clamped Entity Control */
        { &hf_cigi3_conformal_clamped_entity_control,
            { "Conformal Clamped Entity Control", "cigi.conformal_clamped_entity_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Conformal Clamped Entity Control Packet", HFILL }
        },
        { &hf_cigi3_conformal_clamped_entity_control_entity_id,
            { "Entity ID", "cigi.conformal_clamped_entity_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which this packet is applied", HFILL }
        },
        { &hf_cigi3_conformal_clamped_entity_control_yaw,
            { "Yaw (degrees)", "cigi.conformal_clamped_entity_control.yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the instantaneous heading of the entity", HFILL }
        },
        { &hf_cigi3_conformal_clamped_entity_control_lat,
            { "Latitude (degrees)", "cigi.conformal_clamped_entity_control.lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the entity's geodetic latitude", HFILL }
        },
        { &hf_cigi3_conformal_clamped_entity_control_lon,
            { "Longitude (degrees)", "cigi.conformal_clamped_entity_control.lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the entity's geodetic longitude", HFILL }
        },

        /* CIGI4 Conformal Clamped Entity Position */
        { &hf_cigi4_conformal_clamped_entity_position,
            { "Conformal Clamped Entity Control", "cigi.conformal_clamped_entity_position",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Conformal Clamped Entity Control Packet", HFILL }
        },
        { &hf_cigi4_conformal_clamped_entity_position_entity_id,
            { "Entity ID", "cigi.conformal_clamped_entity_position.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which this packet is applied", HFILL }
        },
        { &hf_cigi4_conformal_clamped_entity_position_yaw,
            { "Yaw (degrees)", "cigi.conformal_clamped_entity_position.yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the instantaneous heading of the entity", HFILL }
        },
        { &hf_cigi4_conformal_clamped_entity_position_lat,
            { "Latitude (degrees)", "cigi.conformal_clamped_entity_position.lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the entity's geodetic latitude", HFILL }
        },
        { &hf_cigi4_conformal_clamped_entity_position_lon,
            { "Longitude (degrees)", "cigi.conformal_clamped_entity_position.lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the entity's geodetic longitude", HFILL }
        },

        /* CIGI2 Component Control */
        { &hf_cigi2_component_control,
            { "Component Control", "cigi.component_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Component Control Packet", HFILL }
        },
        { &hf_cigi2_component_control_instance_id,
            { "Instance ID", "cigi.component_control.instance_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the instance of the a class the component being controlled belongs to", HFILL }
        },
        { &hf_cigi2_component_control_component_class,
            { "Component Class", "cigi.component_control.component_class",
                FT_UINT8, BASE_DEC, VALS(cigi2_component_control_component_class_vals), 0x0,
                "Identifies the class the component being controlled is in", HFILL }
        },
        { &hf_cigi2_component_control_component_id,
            { "Component ID", "cigi.component_control.component_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the component of a component class and instance ID this packet will be applied to", HFILL }
        },
        { &hf_cigi2_component_control_component_state,
            { "Component State", "cigi.component_control.component_state",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the commanded state of a component", HFILL }
        },
        { &hf_cigi2_component_control_component_val1,
            { "Component Value 1", "cigi.component_control.component_val1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies a continuous value to be applied to a component", HFILL }
        },
        { &hf_cigi2_component_control_component_val2,
            { "Component Value 2", "cigi.component_control.component_val2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies a continuous value to be applied to a component", HFILL }
        },

        /* CIGI3 Component Control */
        { &hf_cigi3_component_control,
            { "Component Control", "cigi.component_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Component Control Packet", HFILL }
        },
        { &hf_cigi3_component_control_component_id,
            { "Component ID", "cigi.component_control.component_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the component to which the data in this packet should be applied", HFILL }
        },
        { &hf_cigi3_component_control_instance_id,
            { "Instance ID", "cigi.component_control.instance_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the object to which the component belongs", HFILL }
        },
        { &hf_cigi3_component_control_component_class,
            { "Component Class", "cigi.component_control.component_class",
                FT_UINT8, BASE_DEC, VALS(cigi3_component_control_component_class_vals), 0x0f,
                "Identifies the type of object to which the Instance ID parameter refers", HFILL }
        },
        { &hf_cigi3_component_control_component_state,
            { "Component State", "cigi.component_control.component_state",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies a discrete state for the component", HFILL }
        },
        { &hf_cigi3_component_control_data_1,
            { "Component Data 1", "cigi.component_control.data_1",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "User-defined component data", HFILL }
        },
        { &hf_cigi3_component_control_data_2,
            { "Component Data 2", "cigi.component_control.data_2",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "User-defined component data", HFILL }
        },
        { &hf_cigi3_component_control_data_3,
            { "Component Data 3", "cigi.component_control.data_3",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "User-defined component data", HFILL }
        },
        { &hf_cigi3_component_control_data_4,
            { "Component Data 4", "cigi.component_control.data_4",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "User-defined component data", HFILL }
        },
        { &hf_cigi3_component_control_data_5,
            { "Component Data 5", "cigi.component_control.data_5",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "User-defined component data", HFILL }
        },
        { &hf_cigi3_component_control_data_6,
            { "Component Data 6", "cigi.component_control.data_6",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "User-defined component data", HFILL }
        },

        /* CIGI3_3 Component Control */
        { &hf_cigi3_3_component_control_component_class,
            { "Component Class", "cigi.component_control.component_class",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_component_control_component_class_vals), 0x3f,
                "Identifies the type of object to which the Instance ID parameter refers", HFILL }
        },

        /* CIGI4 Component Control */

        /* CIGI3 Short Component Control */
        { &hf_cigi3_short_component_control,
            { "Short Component Control", "cigi.short_component_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Short Component Control Packet", HFILL }
        },
        { &hf_cigi3_short_component_control_component_id,
            { "Component ID", "cigi.short_component_control.component_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the component to which the data in this packet should be applied", HFILL }
        },
        { &hf_cigi3_short_component_control_instance_id,
            { "Instance ID", "cigi.short_component_control.instance_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the object to which the component belongs", HFILL }
        },
        { &hf_cigi3_short_component_control_component_class,
            { "Component Class", "cigi.short_component_control.component_class",
                FT_UINT8, BASE_DEC, VALS(cigi3_short_component_control_component_class_vals), 0x0f,
                "Identifies the type of object to which the Instance ID parameter refers", HFILL }
        },
        { &hf_cigi3_short_component_control_component_state,
            { "Component State", "cigi.short_component_control.component_state",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies a discrete state for the component", HFILL }
        },
        { &hf_cigi3_short_component_control_data_1,
            { "Component Data 1", "cigi.short_component_control.data_1",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "User-defined component data", HFILL }
        },
        { &hf_cigi3_short_component_control_data_2,
            { "Component Data 2", "cigi.short_component_control.data_2",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "User-defined component data", HFILL }
        },

        /* CIGI3_3 Short Component Control */
        { &hf_cigi3_3_short_component_control_component_class,
            { "Component Class", "cigi.short_component_control.component_class",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_short_component_control_component_class_vals), 0x3f,
                "Identifies the type of object to which the Instance ID parameter refers", HFILL }
        },

        /* CIGI4 Short Component Control */

        /* CIGI2 Articulated Parts Control */
        { &hf_cigi2_articulated_parts_control,
            { "Articulated Parts Control", "cigi.art_part_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Articulated Parts Control Packet", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_entity_id,
            { "Entity ID", "cigi.art_part_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the entity to which this data packet will be applied", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_part_id,
            { "Articulated Part ID", "cigi.art_part_control.part_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies which articulated part is controlled with this data packet", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_part_state,
            { "Articulated Part State", "cigi.art_part_control.part_state",
                FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x80,
                "Indicates whether an articulated part is to be shown in the display", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_xoff_enable,
            { "X Offset Enable", "cigi.art_part_control.xoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40,
                "Identifies whether the articulated part x offset in this data packet is manipulated from the host", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_yoff_enable,
            { "Y Offset Enable", "cigi.art_part_control.yoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
                "Identifies whether the articulated part y offset in this data packet is manipulated from the host", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_zoff_enable,
            { "Z Offset Enable", "cigi.art_part_control.zoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Identifies whether the articulated part z offset in this data packet is manipulated from the host", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_roll_enable,
            { "Roll Enable", "cigi.art_part_control.roll_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Identifies whether the articulated part roll enable in this data packet is manipulated from the host", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_pitch_enable,
            { "Pitch Enable", "cigi.art_part_control.pitch_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
                "Identifies whether the articulated part pitch enable in this data packet is manipulated from the host", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_yaw_enable,
            { "Yaw Enable", "cigi.art_part_control.yaw_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
                "Identifies whether the articulated part yaw enable in this data packet is manipulated from the host", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_x_offset,
            { "X Offset (m)", "cigi.art_part_control.x_offset",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the distance along the X axis by which the articulated part should be moved", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_y_offset,
            { "Y Offset (m)", "cigi.art_part_control.y_offset",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the distance along the Y axis by which the articulated part should be moved", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_z_offset,
            { "Z Offset (m)", "cigi.art_part_control.z_offset",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the distance along the Z axis by which the articulated part should be moved", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_roll,
            { "Roll (degrees)", "cigi.art_part_control.roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the roll of this part with respect to the submodel coordinate system", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_pitch,
            { "Pitch (degrees)", "cigi.art_part_control.pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the pitch of this part with respect to the submodel coordinate system", HFILL }
        },
        { &hf_cigi2_articulated_parts_control_yaw,
            { "Yaw (degrees)", "cigi.art_part_control.yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the yaw of this part with respect to the submodel coordinate system", HFILL }
        },

        /* CIGI3 Articulated Part Control */
        { &hf_cigi3_articulated_part_control,
            { "Articulated Part Control", "cigi.art_part_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Articulated Part Control Packet", HFILL }
        },
        { &hf_cigi3_articulated_part_control_entity_id,
            { "Entity ID", "cigi.art_part_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which the articulated part belongs", HFILL }
        },
        { &hf_cigi3_articulated_part_control_part_id,
            { "Articulated Part ID", "cigi.art_part_control.part_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the articulated part to which the data in this packet should be applied", HFILL }
        },
        { &hf_cigi3_articulated_part_control_part_enable,
            { "Articulated Part Enable", "cigi.art_part_control.part_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Determines whether the articulated part submodel should be enabled or disabled within the scene graph", HFILL }
        },
        { &hf_cigi3_articulated_part_control_xoff_enable,
            { "X Offset Enable", "cigi.art_part_control.xoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
                "Determines whether the X Offset parameter of the current packet should be applied to the articulated part", HFILL }
        },
        { &hf_cigi3_articulated_part_control_yoff_enable,
            { "Y Offset Enable", "cigi.art_part_control.yoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
                "Determines whether the Y Offset parameter of the current packet should be applied to the articulated part", HFILL }
        },
        { &hf_cigi3_articulated_part_control_zoff_enable,
            { "Z Offset Enable", "cigi.art_part_control.zoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Determines whether the Z Offset parameter of the current packet should be applied to the articulated part", HFILL }
        },
        { &hf_cigi3_articulated_part_control_roll_enable,
            { "Roll Enable", "cigi.art_part_control.roll_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Determines whether the Roll parameter of the current packet should be applied to the articulated part", HFILL }
        },
        { &hf_cigi3_articulated_part_control_pitch_enable,
            { "Pitch Enable", "cigi.art_part_control.pitch_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
                "Determines whether the Pitch parameter of the current packet should be applied to the articulated part", HFILL }
        },
        { &hf_cigi3_articulated_part_control_yaw_enable,
            { "Yaw Enable", "cigi.art_part_control.yaw_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40,
                "Determines whether the Yaw parameter of the current packet should be applied to the articulated part", HFILL }
        },
        { &hf_cigi3_articulated_part_control_xoff,
            { "X Offset (m)", "cigi.art_part_control.xoff",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the distance of the articulated part along its X axis", HFILL }
        },
        { &hf_cigi3_articulated_part_control_yoff,
            { "Y Offset (m)", "cigi.art_part_control.yoff",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the distance of the articulated part along its Y axis", HFILL }
        },
        { &hf_cigi3_articulated_part_control_zoff,
            { "Z Offset (m)", "cigi.art_part_control.zoff",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the distance of the articulated part along its Z axis", HFILL }
        },
        { &hf_cigi3_articulated_part_control_roll,
            { "Roll (degrees)", "cigi.art_part_control.roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part submodel about its X axis after yaw and pitch have been applied", HFILL }
        },
        { &hf_cigi3_articulated_part_control_pitch,
            { "Pitch (degrees)", "cigi.art_part_control.pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part submodel about its Y axis after yaw has been applied", HFILL }
        },
        { &hf_cigi3_articulated_part_control_yaw,
            { "Yaw (degrees)", "cigi.art_part_control.yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part about its Z axis", HFILL }
        },


        /* CIGI4 Articulated Part Control */

        /* CIGI3 Short Articulated Part Control */
        { &hf_cigi3_short_articulated_part_control,
            { "Short Articulated Part Control", "cigi.short_art_part_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Short Articulated Part Control Packet", HFILL }
        },
        { &hf_cigi3_short_articulated_part_control_entity_id,
            { "Entity ID", "cigi.short_art_part_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which the articulated part(s) belongs", HFILL }
        },
        { &hf_cigi3_short_articulated_part_control_part_id_1,
            { "Articulated Part ID 1", "cigi.short_art_part_control.part_id_1",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies an articulated part to which the data in this packet should be applied", HFILL }
        },
        { &hf_cigi3_short_articulated_part_control_part_id_2,
            { "Articulated Part ID 2", "cigi.short_art_part_control.part_id_2",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies an articulated part to which the data in this packet should be applied", HFILL }
        },
        { &hf_cigi3_short_articulated_part_control_dof_select_1,
            { "DOF Select 1", "cigi.short_art_part_control.dof_select_1",
                FT_UINT8, BASE_DEC, VALS(cigi3_short_articulated_part_control_dof_select_vals), 0x07,
                "Specifies the degree of freedom to which the value of DOF 1 is applied", HFILL }
        },
        { &hf_cigi3_short_articulated_part_control_dof_select_2,
            { "DOF Select 2", "cigi.short_art_part_control.dof_select_2",
                FT_UINT8, BASE_DEC, VALS(cigi3_short_articulated_part_control_dof_select_vals), 0x38,
                "Specifies the degree of freedom to which the value of DOF 2 is applied", HFILL }
        },
        { &hf_cigi3_short_articulated_part_control_part_enable_1,
            { "Articulated Part Enable 1", "cigi.short_art_part_control.part_enable_1",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40,
                "Determines whether the articulated part submodel specified by Articulated Part ID 1 should be enabled or disabled within the scene graph", HFILL }
        },
        { &hf_cigi3_short_articulated_part_control_part_enable_2,
            { "Articulated Part Enable 2", "cigi.short_art_part_control.part_enable_2",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
                "Determines whether the articulated part submodel specified by Articulated Part ID 2 should be enabled or disabled within the scene graph", HFILL }
        },
        { &hf_cigi3_short_articulated_part_control_dof_1,
            { "DOF 1", "cigi.short_art_part_control.dof_1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies either an offset or an angular position for the part identified by Articulated Part ID 1", HFILL }
        },
        { &hf_cigi3_short_articulated_part_control_dof_2,
            { "DOF 2", "cigi.short_art_part_control.dof_2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies either an offset or an angular position for the part identified by Articulated Part ID 2", HFILL }
        },

        /* CIGI4 Short Articulated Part Control */
        { &hf_cigi4_short_articulated_part_control_part_enable_flags,
            { "Request Flags", "cigi.short_art_part_control.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },

        /* CIGI2 Rate Control */
        { &hf_cigi2_rate_control,
            { "Rate Control", "cigi.rate_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Rate Control Packet", HFILL }
        },
        { &hf_cigi2_rate_control_entity_id,
            { "Entity ID", "cigi.rate_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which this data packet will be applied", HFILL }
        },
        { &hf_cigi2_rate_control_part_id,
            { "Articulated Part ID", "cigi.rate_control.part_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies which articulated part is controlled with this data packet", HFILL }
        },
        { &hf_cigi2_rate_control_x_rate,
            { "X Linear Rate (m/s)", "cigi.rate_control.x_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the x component of the velocity vector for the entity being represented", HFILL }
        },
        { &hf_cigi2_rate_control_y_rate,
            { "Y Linear Rate (m/s)", "cigi.rate_control.y_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the y component of the velocity vector for the entity being represented", HFILL }
        },
        { &hf_cigi2_rate_control_z_rate,
            { "Z Linear Rate (m/s)", "cigi.rate_control.z_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the z component of the velocity vector for the entity being represented", HFILL }
        },
        { &hf_cigi2_rate_control_roll_rate,
            { "Roll Angular Rate (degrees/s)", "cigi.rate_control.roll_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the roll angular rate for the entity being represented", HFILL }
        },
        { &hf_cigi2_rate_control_pitch_rate,
            { "Pitch Angular Rate (degrees/s)", "cigi.rate_control.pitch_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the pitch angular rate for the entity being represented", HFILL }
        },
        { &hf_cigi2_rate_control_yaw_rate,
            { "Yaw Angular Rate (degrees/s)", "cigi.rate_control.yaw_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the yaw angular rate for the entity being represented", HFILL }
        },

        /* CIGI3 Rate Control */
        { &hf_cigi3_rate_control,
            { "Rate Control", "cigi.rate_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Rate Control Packet", HFILL }
        },
        { &hf_cigi3_rate_control_entity_id,
            { "Entity ID", "cigi.rate_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which the rate should be applied", HFILL }
        },
        { &hf_cigi3_rate_control_part_id,
            { "Articulated Part ID", "cigi.rate_control.part_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the articulated part to which the rate should be applied", HFILL }
        },
        { &hf_cigi3_rate_control_apply_to_part,
            { "Apply to Articulated Part", "cigi.rate_control.apply_to_part",
                FT_BOOLEAN, 8, NULL, 0x01,
                "Determines whether the rate is applied to the articulated part specified by the Articulated Part ID parameter", HFILL }
        },
        { &hf_cigi3_rate_control_x_rate,
            { "X Linear Rate (m/s)", "cigi.rate_control.x_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the X component of a linear velocity vector", HFILL }
        },
        { &hf_cigi3_rate_control_y_rate,
            { "Y Linear Rate (m/s)", "cigi.rate_control.y_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Y component of a linear velocity vector", HFILL }
        },
        { &hf_cigi3_rate_control_z_rate,
            { "Z Linear Rate (m/s)", "cigi.rate_control.z_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Z component of a linear velocity vector", HFILL }
        },
        { &hf_cigi3_rate_control_roll_rate,
            { "Roll Angular Rate (degrees/s)", "cigi.rate_control.roll_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part submodel about its X axis after yaw and pitch have been applied", HFILL }
        },
        { &hf_cigi3_rate_control_pitch_rate,
            { "Pitch Angular Rate (degrees/s)", "cigi.rate_control.pitch_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part submodel about its Y axis after yaw has been applied", HFILL }
        },
        { &hf_cigi3_rate_control_yaw_rate,
            { "Yaw Angular Rate (degrees/s)", "cigi.rate_control.yaw_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part about its Z axis when its X axis is parallel to that of the entity", HFILL }
        },

        /* CIGI3_2 Rate Control */
        { &hf_cigi3_2_rate_control_coordinate_system,
            { "Coordinate System", "cigi.rate_control.coordinate_system",
                FT_BOOLEAN, 8, TFS(&local_worldparent_tfs), 0x02,
                "Specifies the reference coordinate system to which the linear and angular rates are applied", HFILL }
        },

        /* CIGI4 Velocity Control */
        { & hf_cigi4_velocity_control,
            { "Rate Control", "cigi.rate_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Velocity Control Packet", HFILL }
        },
        { & hf_cigi4_velocity_control_entity_id,
            { "Entity ID", "cigi.rate_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which the rate should be applied", HFILL }
        },
        { & hf_cigi4_velocity_control_part_id,
            { "Articulated Part ID", "cigi.rate_control.part_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the articulated part to which the rate should be applied", HFILL }
        },
        { &hf_cigi4_velocity_control_flags,
            { "Flags", "cigi.rate_control.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { & hf_cigi4_velocity_control_apply_to_part,
            { "Apply to Articulated Part", "cigi.rate_control.apply_to_part",
                FT_BOOLEAN, 8, NULL, 0x01,
                "Determines whether the rate is applied to the articulated part specified by the Articulated Part ID parameter", HFILL }
        },
        { & hf_cigi4_velocity_control_coordinate_system,
            { "Coordinate System", "cigi.rate_control.coordinate_system",
                FT_BOOLEAN, 8, TFS(&local_worldparent_tfs), 0x02,
                "Specifies the reference coordinate system to which the linear and angular rates are applied", HFILL }
        },
        { & hf_cigi4_velocity_control_x_rate,
            { "X Linear Rate (m/s)", "cigi.rate_control.x_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the X component of a linear velocity vector", HFILL }
        },
        { & hf_cigi4_velocity_control_y_rate,
            { "Y Linear Rate (m/s)", "cigi.rate_control.y_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Y component of a linear velocity vector", HFILL }
        },
        { & hf_cigi4_velocity_control_z_rate,
            { "Z Linear Rate (m/s)", "cigi.rate_control.z_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Z component of a linear velocity vector", HFILL }
        },
        { & hf_cigi4_velocity_control_roll_rate,
            { "Roll Angular Rate (degrees/s)", "cigi.rate_control.roll_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part submodel about its X axis after yaw and pitch have been applied", HFILL }
        },
        { & hf_cigi4_velocity_control_pitch_rate,
            { "Pitch Angular Rate (degrees/s)", "cigi.rate_control.pitch_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part submodel about its Y axis after yaw has been applied", HFILL }
        },
        { & hf_cigi4_velocity_control_yaw_rate,
            { "Yaw Angular Rate (degrees/s)", "cigi.rate_control.yaw_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part about its Z axis when its X axis is parallel to that of the entity", HFILL }
        },

        /* CIGI3 Celestial Sphere Control */
        { &hf_cigi3_celestial_sphere_control,
            { "Celestial Sphere Control", "cigi.celestial_sphere_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Celestial Sphere Control Packet", HFILL }
        },
        { &hf_cigi3_celestial_sphere_control_hour,
            { "Hour (h)", "cigi.celestial_sphere_control.hour",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the current hour of the day within the simulation", HFILL }
        },
        { &hf_cigi3_celestial_sphere_control_minute,
            { "Minute (min)", "cigi.celestial_sphere_control.minute",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the current minute of the day within the simulation", HFILL }
        },
        { &hf_cigi3_celestial_sphere_control_ephemeris_enable,
            { "Ephemeris Model Enable", "cigi.celestial_sphere_control.ephemeris_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Controls whether the time of day is static or continuous", HFILL }
        },
        { &hf_cigi3_celestial_sphere_control_sun_enable,
            { "Sun Enable", "cigi.celestial_sphere_control.sun_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
                "Specifies whether the sun is enabled in the sky model", HFILL }
        },
        { &hf_cigi3_celestial_sphere_control_moon_enable,
            { "Moon Enable", "cigi.celestial_sphere_control.moon_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
                "Specifies whether the moon is enabled in the sky model", HFILL }
        },
        { &hf_cigi3_celestial_sphere_control_star_enable,
            { "Star Field Enable", "cigi.celestial_sphere_control.star_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Specifies whether the start field is enabled in the sky model", HFILL }
        },
        { &hf_cigi3_celestial_sphere_control_date_time_valid,
            { "Date/Time Valid", "cigi.celestial_sphere_control.date_time_valid",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Specifies whether the Hour, Minute, and Date parameters are valid", HFILL }
        },
        { &hf_cigi3_celestial_sphere_control_date,
            { "Date (MMDDYYYY)", "cigi.celestial_sphere_control.date",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Specifies the current date within the simulation", HFILL }
        },
        { &hf_cigi3_celestial_sphere_control_star_intensity,
            { "Star Field Intensity (%)", "cigi.celestial_sphere_control.star_intensity",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the intensity of the star field within the sky model", HFILL }
        },

        /* CIGI4 Celestial Sphere Control */
        { &hf_cigi4_celestial_sphere_control_enable_flags,
            { "Flags", "cigi.rate_control.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi4_celestial_sphere_control_seconds,
            { "Second (sec)", "cigi.celestial_sphere_control.seconds",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Specifies the current date within the simulation", HFILL }
        },
        /* The CIGI4 spec shows the date in the opposite order from CIGI3. */
        { &hf_cigi4_celestial_sphere_control_date,
            { "Date (YYYYMMDD)", "cigi.celestial_sphere_control.date",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Specifies the current date within the simulation", HFILL }
        },

        /* CIGI3 Atmosphere Control */
        { &hf_cigi3_atmosphere_control,
            { "Atmosphere Control", "cigi.atmosphere_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Atmosphere Control Packet", HFILL }
        },
        { &hf_cigi3_atmosphere_control_atmospheric_model_enable,
            { "Atmospheric Model Enable", "cigi.atmosphere_control.atmospheric_model_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Specifies whether the IG should use an atmospheric model to determine spectral radiances for sensor applications", HFILL }
        },
        { &hf_cigi3_atmosphere_control_humidity,
            { "Global Humidity (%)", "cigi.atmosphere_control.humidity",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the global humidity of the environment", HFILL }
        },
        { &hf_cigi3_atmosphere_control_air_temp,
            { "Global Air Temperature (degrees C)", "cigi.atmosphere_control.air_temp",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the global air temperature of the environment", HFILL }
        },
        { &hf_cigi3_atmosphere_control_visibility_range,
            { "Global Visibility Range (m)", "cigi.atmosphere_control.visibility_range",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the global visibility range through the atmosphere", HFILL }
        },
        { &hf_cigi3_atmosphere_control_horiz_wind,
            { "Global Horizontal Wind Speed (m/s)", "cigi.atmosphere_control.horiz_wind",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the global wind speed parallel to the ellipsoid-tangential reference plane", HFILL }
        },
        { &hf_cigi3_atmosphere_control_vert_wind,
            { "Global Vertical Wind Speed (m/s)", "cigi.atmosphere_control.vert_wind",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the global vertical wind speed", HFILL }
        },
        { &hf_cigi3_atmosphere_control_wind_direction,
            { "Global Wind Direction (degrees)", "cigi.atmosphere_control.wind_direction",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the global wind direction", HFILL }
        },
        { &hf_cigi3_atmosphere_control_barometric_pressure,
            { "Global Barometric Pressure (mb or hPa)", "cigi.atmosphere_control.barometric_pressure",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the global atmospheric pressure", HFILL }
        },

        /* CIGI4 Atmosphere Control */

        /* CIGI2 Environmental Control */
        { &hf_cigi2_environment_control,
            { "Environment Control", "cigi.env_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Environment Control Packet", HFILL }
        },
        { &hf_cigi2_environment_control_hour,
            { "Hour (h)", "cigi.env_control.hour",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the hour of the day for the ephemeris program within the image generator", HFILL }
        },
        { &hf_cigi2_environment_control_minute,
            { "Minute (min)", "cigi.env_control.minute",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the minute of the hour for the ephemeris program within the image generator", HFILL }
        },
        { &hf_cigi2_environment_control_ephemeris_enable,
            { "Ephemeris Enable", "cigi.env_control.ephemeris_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
                "Identifies whether a continuous time of day or static time of day is used", HFILL }
        },
        { &hf_cigi2_environment_control_humidity,
            { "Humidity (%)", "cigi.env_control.humidity",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                "Specifies the global humidity of the environment", HFILL }
        },
        { &hf_cigi2_environment_control_modtran_enable,
            { "MODTRAN", "cigi.env_control.modtran_enable",
                FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x80,
                "Identifies whether atmospherics will be included in the calculations", HFILL }
        },
        { &hf_cigi2_environment_control_date,
            { "Date (MMDDYYYY)", "cigi.env_control.date",
                FT_INT32, BASE_DEC, NULL, 0x0,
                "Specifies the desired date for use by the ephemeris program within the image generator", HFILL }
        },
        { &hf_cigi2_environment_control_air_temp,
            { "Air Temperature (degrees C)", "cigi.env_control.air_temp",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the global temperature of the environment", HFILL }
        },
        { &hf_cigi2_environment_control_global_visibility,
            { "Global Visibility (m)", "cigi.env_control.global_visibility",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the global visibility", HFILL }
        },
        { &hf_cigi2_environment_control_wind_speed,
            { "Wind Speed (m/s)", "cigi.env_control.wind_speed",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the global wind speed", HFILL }
        },
        { &hf_cigi2_environment_control_wind_direction,
            { "Wind Direction (degrees)", "cigi.env_control.wind_direction",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the global wind direction", HFILL }
        },
        { &hf_cigi2_environment_control_pressure,
            { "Barometric Pressure (mb)", "cigi.env_control.pressure",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Controls the atmospheric pressure input into MODTRAN", HFILL }
        },
        { &hf_cigi2_environment_control_aerosol,
            { "Aerosol (gm/m^3)", "cigi.env_control.aerosol",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Controls the liquid water content for the defined atmosphere", HFILL }
        },

        /* CIGI3 Environmental Region Control */
        { &hf_cigi3_environmental_region_control,
            { "Environmental Region Control", "cigi.env_region_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Environmental Region Control Packet", HFILL }
        },
        { &hf_cigi3_environmental_region_control_region_id,
            { "Region ID", "cigi.env_region_control.region_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the environmental region to which the data in this packet will be applied", HFILL }
        },
        { &hf_cigi3_environmental_region_control_region_state,
            { "Region State", "cigi.env_region_control.region_state",
                FT_UINT8, BASE_DEC, VALS(cigi3_environmental_region_control_region_state_vals), 0x03,
                "Specifies whether the region should be active or destroyed", HFILL }
        },
        { &hf_cigi3_environmental_region_control_merge_weather,
            { "Merge Weather Properties", "cigi.env_region_control.merge_weather",
                FT_BOOLEAN, 8, TFS(&cigi3_environmental_region_control_merge_properties_tfs), 0x04,
                "Specifies whether atmospheric conditions within this region should be merged with those of other regions within areas of overlap", HFILL }
        },
        { &hf_cigi3_environmental_region_control_merge_aerosol,
            { "Merge Aerosol Concentrations", "cigi.env_region_control.merge_aerosol",
                FT_BOOLEAN, 8, TFS(&cigi3_environmental_region_control_merge_properties_tfs), 0x08,
                "Specifies whether the concentrations of aerosols found within this region should be merged with those of other regions within areas of overlap", HFILL }
        },
        { &hf_cigi3_environmental_region_control_merge_maritime,
            { "Merge Maritime Surface Conditions", "cigi.env_region_control.merge_maritime",
                FT_BOOLEAN, 8, TFS(&cigi3_environmental_region_control_merge_properties_tfs), 0x10,
                "Specifies whether the maritime surface conditions found within this region should be merged with those of other regions within areas of overlap", HFILL }
        },
        { &hf_cigi3_environmental_region_control_merge_terrestrial,
            { "Merge Terrestrial Surface Conditions", "cigi.env_region_control.merge_terrestrial",
                FT_BOOLEAN, 8, TFS(&cigi3_environmental_region_control_merge_properties_tfs), 0x20,
                "Specifies whether the terrestrial surface conditions found within this region should be merged with those of other regions within areas of overlap", HFILL }
        },
        { &hf_cigi3_environmental_region_control_lat,
            { "Latitude (degrees)", "cigi.env_region_control.lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the geodetic latitude of the center of the rounded rectangle", HFILL }
        },
        { &hf_cigi3_environmental_region_control_lon,
            { "Longitude (degrees)", "cigi.env_region_control.lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the geodetic longitude of the center of the rounded rectangle", HFILL }
        },
        { &hf_cigi3_environmental_region_control_size_x,
            { "Size X (m)", "cigi.env_region_control.size_x",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the length of the environmental region along its X axis at the geoid surface", HFILL }
        },
        { &hf_cigi3_environmental_region_control_size_y,
            { "Size Y (m)", "cigi.env_region_control.size_y",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the length of the environmental region along its Y axis at the geoid surface", HFILL }
        },
        { &hf_cigi3_environmental_region_control_corner_radius,
            { "Corner Radius (m)", "cigi.env_region_control.corner_radius",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius of the corner of the rounded rectangle", HFILL }
        },
        { &hf_cigi3_environmental_region_control_rotation,
            { "Rotation (degrees)", "cigi.env_region_control.rotation",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the yaw angle of the rounded rectangle", HFILL }
        },
        { &hf_cigi3_environmental_region_control_transition_perimeter,
            { "Transition Perimeter (m)", "cigi.env_region_control.transition_perimeter",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the width of the transition perimeter around the environmental region", HFILL }
        },


        /* CIGI4 Environmental Region Control */

        /* CIGI2 Weather Control */
        { &hf_cigi2_weather_control,
            { "Weather Control", "cigi.weather_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Weather Control Packet", HFILL }
        },
        { &hf_cigi2_weather_control_entity_id,
            { "Entity ID", "cigi.weather_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the entity's ID", HFILL }
        },
        { &hf_cigi2_weather_control_weather_enable,
            { "Weather Enable", "cigi.weather_control.weather_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
                "Indicates whether the phenomena specified by this data packet is visible", HFILL }
        },
        { &hf_cigi2_weather_control_scud_enable,
            { "Scud Enable", "cigi.weather_control.scud_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40,
                "Indicates whether there will be scud effects applied to the phenomenon specified by this data packet", HFILL }
        },
        { &hf_cigi2_weather_control_random_winds,
            { "Random Winds Aloft", "cigi.weather_control.random_winds",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
                "Indicates whether a random frequency and duration should be applied to the winds aloft value", HFILL }
        },
        { &hf_cigi2_weather_control_severity,
            { "Severity", "cigi.weather_control.severity",
                FT_UINT8, BASE_DEC, NULL, 0x1c,
                "Indicates the severity of the weather phenomenon", HFILL }
        },
        { &hf_cigi2_weather_control_phenomenon_type,
            { "Phenomenon Type", "cigi.weather_control.phenomenon_type",
                FT_UINT16, BASE_DEC, VALS(cigi2_weather_control_phenomenon_type_vals), 0x0,
                "Identifies the type of weather described by this data packet", HFILL }
        },
        { &hf_cigi2_weather_control_air_temp,
            { "Air Temperature (degrees C)", "cigi.weather_control.air_temp",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the local temperature inside the weather phenomenon", HFILL }
        },
        { &hf_cigi2_weather_control_opacity,
            { "Opacity (%)", "cigi.weather_control.opacity",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the opacity of the weather phenomenon", HFILL }
        },
        { &hf_cigi2_weather_control_scud_frequency,
            { "Scud Frequency (%)", "cigi.weather_control.scud_frequency",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the frequency for the scud effect", HFILL }
        },
        { &hf_cigi2_weather_control_coverage,
            { "Coverage (%)", "cigi.weather_control.coverage",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the amount of area coverage a particular phenomenon has over the specified global visibility range given in the environment control data packet", HFILL }
        },
        { &hf_cigi2_weather_control_elevation,
            { "Elevation (m)", "cigi.weather_control.elevation",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the base altitude of the weather phenomenon", HFILL }
        },
        { &hf_cigi2_weather_control_thickness,
            { "Thickness (m)", "cigi.weather_control.thickness",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the vertical thickness of the weather phenomenon", HFILL }
        },
        { &hf_cigi2_weather_control_transition_band,
            { "Transition Band (m)", "cigi.weather_control.transition_band",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates a vertical transition band both above and below a phenomenon", HFILL }
        },
        { &hf_cigi2_weather_control_wind_speed,
            { "Winds Aloft Speed", "cigi.weather_control.wind_speed",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the local wind speed applied to the phenomenon", HFILL }
        },
        { &hf_cigi2_weather_control_wind_direction,
            { "Winds Aloft Direction (degrees)", "cigi.weather_control.wind_direction",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates local direction of the wind applied to the phenomenon", HFILL }
        },

        /* CIGI3 Weather Control */
        { &hf_cigi3_weather_control,
            { "Weather Control", "cigi.weather_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Weather Control Packet", HFILL }
        },
        { &hf_cigi3_weather_control_entity_region_id,
            { "Entity ID/Region ID", "cigi.weather_control.entity_region_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which the weather attributes in this packet are applied", HFILL }
        },
        { &hf_cigi3_weather_control_layer_id,
            { "Layer ID", "cigi.weather_control.layer_id",
                FT_UINT8, BASE_DEC, VALS(cigi3_weather_control_layer_id_vals), 0x0,
                "Specifies the weather layer to which the data in this packet are applied", HFILL }
        },
        { &hf_cigi3_weather_control_humidity,
            { "Humidity (%)", "cigi.weather_control.humidity",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the humidity within the weather layer", HFILL }
        },
        { &hf_cigi3_weather_control_weather_enable,
            { "Weather Enable", "cigi.weather_control.weather_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Specifies whether a weather layer and its atmospheric effects are enabled", HFILL }
        },
        { &hf_cigi3_weather_control_scud_enable,
            { "Scud Enable", "cigi.weather_control.scud_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
                "Specifies whether weather layer produces scud effects within its transition bands", HFILL }
        },
        { &hf_cigi3_weather_control_random_winds_enable,
            { "Random Winds Enable", "cigi.weather_control.random_winds_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
                "Specifies whether a random frequency and duration should be applied to the local wind effects", HFILL }
        },
        { &hf_cigi3_weather_control_random_lightning_enable,
            { "Random Lightning Enable", "cigi.weather_control.random_lightning_enable",
                FT_UINT8, BASE_DEC, NULL, 0x08,
                "Specifies whether the weather layer exhibits random lightning effects", HFILL }
        },
        { &hf_cigi3_weather_control_cloud_type,
            { "Cloud Type", "cigi.weather_control.cloud_type",
                FT_UINT8, BASE_DEC, VALS(cigi3_weather_control_cloud_type_vals), 0xf0,
                "Specifies the type of clouds contained within the weather layer", HFILL }
        },
        { &hf_cigi3_weather_control_scope,
            { "Scope", "cigi.weather_control.scope",
                FT_UINT8, BASE_DEC, VALS(cigi3_weather_control_scope_vals), 0x03,
                "Specifies whether the weather is global, regional, or assigned to an entity", HFILL }
        },
        { &hf_cigi3_weather_control_severity,
            { "Severity", "cigi.weather_control.severity",
                FT_UINT8, BASE_DEC, NULL, 0x1c,
                "Specifies the severity of the weather layer", HFILL }
        },
        { &hf_cigi3_weather_control_air_temp,
            { "Air Temperature (degrees C)", "cigi.weather_control.air_temp",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the temperature within the weather layer", HFILL }
        },
        { &hf_cigi3_weather_control_visibility_range,
            { "Visibility Range (m)", "cigi.weather_control.visibility_range",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the visibility range through the weather layer", HFILL }
        },
        { &hf_cigi3_weather_control_scud_frequency,
            { "Scud Frequency (%)", "cigi.weather_control.scud_frequency",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the frequency of scud within the transition bands above and/or below a cloud or fog layer", HFILL }
        },
        { &hf_cigi3_weather_control_coverage,
            { "Coverage (%)", "cigi.weather_control.coverage",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the amount of area coverage for the weather layer", HFILL }
        },
        { &hf_cigi3_weather_control_base_elevation,
            { "Base Elevation (m)", "cigi.weather_control.base_elevation",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the altitude of the base of the weather layer", HFILL }
        },
        { &hf_cigi3_weather_control_thickness,
            { "Thickness (m)", "cigi.weather_control.thickness",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the vertical thickness of the weather layer", HFILL }
        },
        { &hf_cigi3_weather_control_transition_band,
            { "Transition Band (m)", "cigi.weather_control.transition_band",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the height of a vertical transition band both above and below the weather layer", HFILL }
        },
        { &hf_cigi3_weather_control_horiz_wind,
            { "Horizontal Wind Speed (m/s)", "cigi.weather_control.horiz_wind",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the local wind speed parallel to the ellipsoid-tangential reference plane", HFILL }
        },
        { &hf_cigi3_weather_control_vert_wind,
            { "Vertical Wind Speed (m/s)", "cigi.weather_control.vert_wind",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the local vertical wind speed", HFILL }
        },
        { &hf_cigi3_weather_control_wind_direction,
            { "Wind Direction (degrees)", "cigi.weather_control.wind_direction",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the local wind direction", HFILL }
        },
        { &hf_cigi3_weather_control_barometric_pressure,
            { "Barometric Pressure (mb or hPa)", "cigi.weather_control.barometric_pressure",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the atmospheric pressure within the weather layer", HFILL }
        },
        { &hf_cigi3_weather_control_aerosol_concentration,
            { "Aerosol Concentration (g/m^3)", "cigi.weather_control.aerosol_concentration",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the concentration of water, smoke, dust, or other particles suspended in the air", HFILL }
        },


        /* CIGI4 Weather Control */
        { &hf_cigi4_weather_control_flags,
            { "Request Flags", "cigi.weather_control.flags",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi4_weather_control_top_scud_enable,
            { "Top Scud Enable", "cigi.weather_control.top_scud_enable",
                FT_UINT8, BASE_DEC, NULL, 0x20,
                "Specifies whether the weather layer produces scud effects", HFILL }
        },
        { &hf_cigi4_weather_control_top_scud_freq,
            { "Top Scud Frequency (%)", "cigi.weather_control.top_scud_frequency",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the frequency of scud within the transition band above a cloud or fog layer", HFILL }
        },
        { &hf_cigi4_weather_control_top_transition_band,
            { "Top Transition Band Thickness (m)", "cigi.weather_control.top_transition_band",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the height of a vertical transition band above the weather layer", HFILL }
        },

        /* CIGI3 Maritime Surface Conditions Control */
        { &hf_cigi3_maritime_surface_conditions_control,
            { "Maritime Surface Conditions Control", "cigi.maritime_surface_conditions_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Maritime Surface Conditions Control Packet", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_control_entity_region_id,
            { "Entity ID/Region ID", "cigi.maritime_surface_conditions_control.entity_region_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which the surface attributes in this packet are applied or specifies the region to which the surface attributes are confined", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_control_surface_conditions_enable,
            { "Surface Conditions Enable", "cigi.maritime_surface_conditions_control.surface_conditions_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Determines the state of the specified surface conditions", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_control_whitecap_enable,
            { "Whitecap Enable", "cigi.maritime_surface_conditions_control.whitecap_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
                "Determines whether whitecaps are enabled", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_control_scope,
            { "Scope", "cigi.maritime_surface_conditions_control.scope",
                FT_UINT8, BASE_DEC, VALS(cigi3_maritime_surface_conditions_control_scope_vals), 0x0c,
                "Specifies whether this packet is applied globally, applied to region, or assigned to an entity", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_control_sea_surface_height,
            { "Sea Surface Height (m)", "cigi.maritime_surface_conditions_control.sea_surface_height",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the height of the water above MSL at equilibrium", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_control_surface_water_temp,
            { "Surface Water Temperature (degrees C)", "cigi.maritime_surface_conditions_control.surface_water_temp",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the water temperature at the surface", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_control_surface_clarity,
            { "Surface Clarity (%)", "cigi.maritime_surface_conditions_control.surface_clarity",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the clarity of the water at its surface", HFILL }
        },


        /* CIGI4 Maritime Surface Conditions Control */

        /* CIGI3 Wave Control */
        { &hf_cigi3_wave_control,
            { "Wave Control", "cigi.wave_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Wave Control Packet", HFILL }
        },
        { &hf_cigi3_wave_control_entity_region_id,
            { "Entity ID/Region ID", "cigi.wave_control.entity_region_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the surface entity for which the wave is defined or specifies the environmental region for which the wave is defined", HFILL }
        },
        { &hf_cigi3_wave_control_wave_id,
            { "Wave ID", "cigi.wave_control.wave_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the wave to which the attributes in this packet are applied", HFILL }
        },
        { &hf_cigi3_wave_control_wave_enable,
            { "Wave Enable", "cigi.wave_control.wave_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Determines whether the wave is enabled or disabled", HFILL }
        },
        { &hf_cigi3_wave_control_scope,
            { "Scope", "cigi.wave_control.scope",
                FT_UINT8, BASE_DEC, VALS(cigi3_wave_control_scope_vals), 0x06,
                "Specifies whether the wave is defined for global, regional, or entity-controlled maritime surface conditions", HFILL }
        },
        { &hf_cigi3_wave_control_breaker_type,
            { "Breaker Type", "cigi.wave_control.breaker_type",
                FT_UINT8, BASE_DEC, VALS(cigi3_wave_control_breaker_type_vals), 0x18,
                "Specifies the type of breaker within the surf zone", HFILL }
        },
        { &hf_cigi3_wave_control_height,
            { "Wave Height (m)", "cigi.wave_control.height",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the average vertical distance from trough to crest produced by the wave", HFILL }
        },
        { &hf_cigi3_wave_control_wavelength,
            { "Wavelength (m)", "cigi.wave_control.wavelength",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the distance from a particular phase on a wave to the same phase on an adjacent wave", HFILL }
        },
        { &hf_cigi3_wave_control_period,
            { "Period (s)", "cigi.wave_control.period",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the time required for one complete oscillation of the wave", HFILL }
        },
        { &hf_cigi3_wave_control_direction,
            { "Direction (degrees)", "cigi.wave_control.direction",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the direction in which the wave propagates", HFILL }
        },
        { &hf_cigi3_wave_control_phase_offset,
            { "Phase Offset (degrees)", "cigi.wave_control.phase_offset",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies a phase offset for the wave", HFILL }
        },
        { &hf_cigi3_wave_control_leading,
            { "Leading (degrees)", "cigi.wave_control.leading",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the phase angle at which the crest occurs", HFILL }
        },

        /* CIGI4 Wave Control */

        /* CIGI3 Terrestrial Surface Conditions Control */
        { &hf_cigi3_terrestrial_surface_conditions_control,
            { "Terrestrial Surface Conditions Control", "cigi.terrestrial_surface_conditions_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Terrestrial Surface Conditions Control Packet", HFILL }
        },
        { &hf_cigi3_terrestrial_surface_conditions_control_entity_region_id,
            { "Entity ID/Region ID", "cigi.terrestrial_surface_conditions_control.entity_region_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the environmental entity to which the surface condition attributes in this packet are applied", HFILL }
        },
        { &hf_cigi3_terrestrial_surface_conditions_control_surface_condition_id,
            { "Surface Condition ID", "cigi.terrestrial_surface_conditions_control.surface_condition_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies a surface condition or contaminant", HFILL }
        },
        { &hf_cigi3_terrestrial_surface_conditions_control_surface_condition_enable,
            { "Surface Condition Enable", "cigi.terrestrial_surface_conditions_control.surface_condition_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Specifies whether the surface condition attribute identified by the Surface Condition ID parameter should be enabled", HFILL }
        },
        { &hf_cigi3_terrestrial_surface_conditions_control_scope,
            { "Scope", "cigi.terrestrial_surface_conditions_control.scope",
                FT_UINT8, BASE_DEC, VALS(cigi3_terrestrial_surface_conditions_control_scope_vals), 0x06,
                "Determines whether the specified surface conditions are applied globally, regionally, or to an environmental entity", HFILL }
        },
        { &hf_cigi3_terrestrial_surface_conditions_control_severity,
            { "Severity", "cigi.terrestrial_surface_conditions_control.severity",
                FT_UINT8, BASE_DEC, NULL, 0xf8,
                "Determines the degree of severity for the specified surface contaminant(s)", HFILL }
        },
        { &hf_cigi3_terrestrial_surface_conditions_control_coverage,
            { "Coverage (%)", "cigi.terrestrial_surface_conditions_control.coverage",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Determines the degree of coverage of the specified surface contaminant", HFILL }
        },

        /* CIGI4 Terrestrial Surface Conditions Control */

        /* CIGI2 View Control */
        { &hf_cigi2_view_control,
            { "View Control", "cigi.view_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "View Control Packet", HFILL }
        },
        { &hf_cigi2_view_control_entity_id,
            { "Entity ID", "cigi.view_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity to which this view should be attached", HFILL }
        },
        { &hf_cigi2_view_control_view_id,
            { "View ID", "cigi.view_control.view_id",
                FT_UINT8, BASE_DEC, NULL, 0xf8,
                "Specifies which view position is associated with offsets and rotation specified by this data packet", HFILL }
        },
        { &hf_cigi2_view_control_view_group,
            { "View Group Select", "cigi.view_control.view_group",
                FT_UINT8, BASE_DEC, NULL, 0x07,
                "Specifies which view group is to be controlled by the offsets", HFILL }
        },
        { &hf_cigi2_view_control_xoff_enable,
            { "X Offset Enable", "cigi.view_control.xoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
                "Identifies whether the x offset parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi2_view_control_yoff_enable,
            { "Y Offset Enable", "cigi.view_control.yoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40,
                "Identifies whether the y offset parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi2_view_control_zoff_enable,
            { "Z Offset Enable", "cigi.view_control.zoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
                "Identifies whether the z offset parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi2_view_control_roll_enable,
            { "Roll Enable", "cigi.view_control.roll_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Identifies whether the roll parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi2_view_control_pitch_enable,
            { "Pitch Enable", "cigi.view_control.pitch_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Identifies whether the pitch parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi2_view_control_yaw_enable,
            { "Yaw Enable", "cigi.view_control.yaw_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
                "Identifies whether the yaw parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi2_view_control_x_offset,
            { "X Offset (m)", "cigi.view_control.x_offset",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Defines the X component of the view offset vector along the entity's longitudinal axis", HFILL }
        },
        { &hf_cigi2_view_control_y_offset,
            { "Y Offset", "cigi.view_control.y_offset",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Defines the Y component of the view offset vector along the entity's lateral axis", HFILL }
        },
        { &hf_cigi2_view_control_z_offset,
            { "Z Offset", "cigi.view_control.z_offset",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Defines the Z component of the view offset vector along the entity's vertical axis", HFILL }
        },
        { &hf_cigi2_view_control_roll,
            { "Roll (degrees)", "cigi.view_control.roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "The rotation about the view's X axis", HFILL }
        },
        { &hf_cigi2_view_control_pitch,
            { "Pitch (degrees)", "cigi.view_control.pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "The rotation about the view's Y axis", HFILL }
        },
        { &hf_cigi2_view_control_yaw,
            { "Yaw (degrees)", "cigi.view_control.yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "The rotation about the view's Z axis", HFILL }
        },

        /* CIGI3 View Control */
        { &hf_cigi3_view_control,
            { "View Control", "cigi.view_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "View Control Packet", HFILL }
        },
        { &hf_cigi3_view_control_view_id,
            { "View ID", "cigi.view_control.view_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the view to which the contents of this packet should be applied", HFILL }
        },
        { &hf_cigi3_view_control_group_id,
            { "Group ID", "cigi.view_control.group_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the view group to which the contents of this packet are applied", HFILL }
        },
        { &hf_cigi3_view_control_xoff_enable,
            { "X Offset Enable", "cigi.view_control.xoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Determines whether the X Offset parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi3_view_control_yoff_enable,
            { "Y Offset Enable", "cigi.view_control.yoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
                "Determines whether the Y Offset parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi3_view_control_zoff_enable,
            { "Z Offset Enable", "cigi.view_control.zoff_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
                "Determines whether the Z Offset parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi3_view_control_roll_enable,
            { "Roll Enable", "cigi.view_control.roll_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Determines whether the Roll parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi3_view_control_pitch_enable,
            { "Pitch Enable", "cigi.view_control.pitch_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Determines whether the Pitch parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi3_view_control_yaw_enable,
            { "Yaw Enable", "cigi.view_control.yaw_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
                "Determines whether the Yaw parameter should be applied to the specified view or view group", HFILL }
        },
        { &hf_cigi3_view_control_entity_id,
            { "Entity ID", "cigi.view_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity to which the view or view group should be attached", HFILL }
        },
        { &hf_cigi3_view_control_xoff,
            { "X Offset (m)", "cigi.view_control.xoff",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the position of the view eyepoint along the X axis of the entity specified by the Entity ID parameter", HFILL }
        },
        { &hf_cigi3_view_control_yoff,
            { "Y Offset (m)", "cigi.view_control.yoff",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the position of the view eyepoint along the Y axis of the entity specified by the Entity ID parameter", HFILL }
        },
        { &hf_cigi3_view_control_zoff,
            { "Z Offset (m)", "cigi.view_control.zoff",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the position of the view eyepoint along the Z axis of the entity specified by the Entity ID parameter", HFILL }
        },
        { &hf_cigi3_view_control_roll,
            { "Roll (degrees)", "cigi.view_control.roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the view or view group about its X axis after yaw and pitch have been applied", HFILL }
        },
        { &hf_cigi3_view_control_pitch,
            { "Pitch (degrees)", "cigi.view_control.pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the view or view group about its Y axis after yaw has been applied", HFILL }
        },
        { &hf_cigi3_view_control_yaw,
            { "Yaw (degrees)", "cigi.view_control.yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the view or view group about its Z axis", HFILL }
        },


        /* CIGI4 View Control */
        { &hf_cigi4_view_control_enable_flags,
            { "Request Flags", "cigi.view_control.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },

        /* CIGI2 Sensor Control */
        { &hf_cigi2_sensor_control,
            { "Sensor Control", "cigi.sensor_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Sensor Control Packet", HFILL }
        },
        { &hf_cigi2_sensor_control_view_id,
            { "View ID", "cigi.sensor_control.view_id",
                FT_UINT8, BASE_DEC, NULL, 0xf8,
                "Dictates to which view the corresponding sensor is assigned, regardless of the view group", HFILL }
        },
        { &hf_cigi2_sensor_control_sensor_enable,
            { "Sensor On/Off", "cigi.sensor_control.sensor_enable",
                FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x04,
                "Indicates whether the sensor is turned on or off", HFILL }
        },
        { &hf_cigi2_sensor_control_polarity,
            { "Polarity", "cigi.sensor_control.polarity",
                FT_BOOLEAN, 8, TFS(&black_white_tfs), 0x02,
                "Indicates whether this sensor is showing white hot or black hot", HFILL }
        },
        { &hf_cigi2_sensor_control_line_dropout,
            { "Line-by-Line Dropout", "cigi.sensor_control.line_dropout",
                FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x01,
                "Indicates whether the line-by-line dropout feature is enabled", HFILL }
        },
        { &hf_cigi2_sensor_control_sensor_id,
            { "Sensor ID", "cigi.sensor_control.sensor_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the sensor to which this packet should be applied", HFILL }
        },
        { &hf_cigi2_sensor_control_track_mode,
            { "Track Mode", "cigi.sensor_control.track_mode",
                FT_UINT8, BASE_DEC, VALS(cigi2_sensor_control_track_mode_vals), 0xf0,
                "Indicates which track mode the sensor should be", HFILL }
        },
        { &hf_cigi2_sensor_control_auto_gain,
            { "Automatic Gain", "cigi.sensor_control.auto_gain",
                FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x08,
                "When set to \"on,\" cause the weapons sensor to automatically adjust the gain value to optimize the brightness and contrast of the sensor display", HFILL }
        },
        { &hf_cigi2_sensor_control_track_polarity,
            { "Track White/Black", "cigi.sensor_control.track_polarity",
                FT_BOOLEAN, 8, TFS(&black_white_tfs), 0x04,
                "Identifies whether the weapons sensor will track wither white or black", HFILL }
        },
        { &hf_cigi2_sensor_control_gain,
            { "Gain", "cigi.sensor_control.gain",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the gain value for the weapon sensor option", HFILL }
        },
        { &hf_cigi2_sensor_control_level,
            { "Level", "cigi.sensor_control.level",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the level value for the weapon sensor option", HFILL }
        },
        { &hf_cigi2_sensor_control_ac_coupling,
            { "AC Coupling", "cigi.sensor_control.ac_coupling",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the AC Coupling decay rate for the weapon sensor option", HFILL }
        },
        { &hf_cigi2_sensor_control_noise,
            { "Noise", "cigi.sensor_control.noise",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the detector-noise gain for the weapon sensor option", HFILL }
        },

        /* CIGI3 Sensor Control */
        { &hf_cigi3_sensor_control,
            { "Sensor Control", "cigi.sensor_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Sensor Control Packet", HFILL }
        },
        { &hf_cigi3_sensor_control_view_id,
            { "View ID", "cigi.sensor_control.view_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the view to which the specified sensor is assigned", HFILL }
        },
        { &hf_cigi3_sensor_control_sensor_id,
            { "Sensor ID", "cigi.sensor_control.sensor_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the sensor to which the data in this packet are applied", HFILL }
        },
        { &hf_cigi3_sensor_control_sensor_on_off,
            { "Sensor On/Off", "cigi.sensor_control.sensor_on_off",
                FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x01,
                "Specifies whether the sensor is turned on or off", HFILL }
        },
        { &hf_cigi3_sensor_control_polarity,
            { "Polarity", "cigi.sensor_control.polarity",
                FT_BOOLEAN, 8, TFS(&cigi3_sensor_control_polarity_tfs), 0x02,
                "Specifies whether the sensor shows white hot or black hot", HFILL }
        },
        { &hf_cigi3_sensor_control_line_dropout_enable,
            { "Line-by-Line Dropout Enable", "cigi.sensor_control.line_dropout_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
                "Specifies whether line-by-line dropout is enabled", HFILL }
        },
        { &hf_cigi3_sensor_control_auto_gain,
            { "Automatic Gain", "cigi.sensor_control.auto_gain",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Specifies whether the sensor automatically adjusts the gain value to optimize the brightness and contrast of the sensor display", HFILL }
        },
        { &hf_cigi3_sensor_control_track_white_black,
            { "Track White/Black", "cigi.sensor_control.track_white_black",
                FT_BOOLEAN, 8, TFS(&black_white_tfs), 0x10,
                "Specifies whether the sensor tracks white or black", HFILL }
        },
        { &hf_cigi3_sensor_control_track_mode,
            { "Track Mode", "cigi.sensor_control.track_mode",
                FT_UINT8, BASE_DEC, VALS(cigi3_sensor_control_track_mode_vals), 0xe0,
                "Specifies which track mode the sensor should use", HFILL }
        },
        { &hf_cigi3_sensor_control_response_type,
            { "Response Type", "cigi.sensor_control.response_type",
                FT_BOOLEAN, 8, TFS(&extended_normal_tfs), 0x01,
                "Specifies whether the IG should return a Sensor Response packet or a Sensor Extended Response packet", HFILL }
        },
        { &hf_cigi3_sensor_control_gain,
            { "Gain", "cigi.sensor_control.gain",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the contrast for the sensor display", HFILL }
        },
        { &hf_cigi3_sensor_control_level,
            { "Level", "cigi.sensor_control.level",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the brightness for the sensor display", HFILL }
        },
        { &hf_cigi3_sensor_control_ac_coupling,
            { "AC Coupling (microseconds)", "cigi.sensor_control.ac_coupling",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the AC coupling decay constant for the sensor display", HFILL }
        },
        { &hf_cigi3_sensor_control_noise,
            { "Noise", "cigi.sensor_control.noise",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the amount of detector noise for the sensor", HFILL }
        },


        /* CIGI4 Sensor Control */

        /* CIGI3 Motion Tracker Control */
        { &hf_cigi3_motion_tracker_control,
            { "Motion Tracker Control", "cigi.motion_tracker_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Motion Tracker Control Packet", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_view_group_id,
            { "View/View Group ID", "cigi.motion_tracker_control.view_group_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the view or view group to which the tracking device is attached", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_tracker_id,
            { "Tracker ID", "cigi.motion_tracker_control.tracker_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the tracker whose state the data in this packet represents", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_tracker_enable,
            { "Tracker Enable", "cigi.motion_tracker_control.tracker_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Specifies whether the tracking device is enabled", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_boresight_enable,
            { "Boresight Enable", "cigi.motion_tracker_control.boresight_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
                "Sets the boresight state of the external tracking device", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_x_enable,
            { "X Enable", "cigi.motion_tracker_control.x_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
                "Used to enable or disable the X-axis position of the motion tracker", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_y_enable,
            { "Y Enable", "cigi.motion_tracker_control.y_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Used to enable or disable the Y-axis position of the motion tracker", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_z_enable,
            { "Z Enable", "cigi.motion_tracker_control.z_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Used to enable or disable the Z-axis position of the motion tracker", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_roll_enable,
            { "Roll Enable", "cigi.motion_tracker_control.roll_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
                "Used to enable or disable the roll of the motion tracker", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_pitch_enable,
            { "Pitch Enable", "cigi.motion_tracker_control.pitch_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40,
                "Used to enable or disable the pitch of the motion tracker", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_yaw_enable,
            { "Yaw Enable", "cigi.motion_tracker_control.yaw_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
                "Used to enable or disable the yaw of the motion tracker", HFILL }
        },
        { &hf_cigi3_motion_tracker_control_view_group_select,
            { "View/View Group Select", "cigi.motion_tracker_control.view_group_select",
                FT_BOOLEAN, 8, TFS(&cigi3_motion_tracker_control_view_group_select_tfs), 0x01,
                "Specifies whether the tracking device is attached to a single view or a view group", HFILL }
        },

        /* CIGI4 Motion Tracker Control */

        /* CIGI3 Earth Reference Model Definition */
        { &hf_cigi3_earth_reference_model_definition,
            { "Earth Reference Model Definition", "cigi.earth_ref_model_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Earth Reference Model Definition Packet", HFILL }
        },
        { &hf_cigi3_earth_reference_model_definition_erm_enable,
            { "Custom ERM Enable", "cigi.earth_ref_model_def.erm_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Specifies whether the IG should use the Earth Reference Model defined by this packet", HFILL }
        },
        { &hf_cigi3_earth_reference_model_definition_equatorial_radius,
            { "Equatorial Radius (m)", "cigi.earth_ref_model_def.equatorial_radius",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the semi-major axis of the ellipsoid", HFILL }
        },
        { &hf_cigi3_earth_reference_model_definition_flattening,
            { "Flattening (m)", "cigi.earth_ref_model_def.flattening",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the flattening of the ellipsoid", HFILL }
        },

        /* CIGI4 Earth Reference Model Definition */

        /* CIGI2 Trajectory Definition */
        { &hf_cigi2_trajectory_definition,
            { "Trajectory Definition", "cigi.trajectory_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Trajectory Definition Packet", HFILL }
        },
        { &hf_cigi2_trajectory_definition_entity_id,
            { "Entity ID", "cigi.trajectory_def.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates which entity is being influenced by this trajectory behavior", HFILL }
        },
        { &hf_cigi2_trajectory_definition_acceleration,
            { "Acceleration Factor (m/s^2)", "cigi.trajectory_def.acceleration",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the acceleration factor that will be applied to the Vz component of the velocity vector over time to simulate the effects of gravity on the object", HFILL }
        },
        { &hf_cigi2_trajectory_definition_retardation,
            { "Retardation Rate (m/s)", "cigi.trajectory_def.retardation",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates what retardation factor will be applied to the object's motion", HFILL }
        },
        { &hf_cigi2_trajectory_definition_terminal_velocity,
            { "Terminal Velocity (m/s)", "cigi.trajectory_def.terminal_velocity",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates what final velocity the object will be allowed to obtain", HFILL }
        },

        /* CIGI3 Trajectory Definition */
        { &hf_cigi3_trajectory_definition,
            { "Trajectory Definition", "cigi.trajectory_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Trajectory Definition Packet", HFILL }
        },
        { &hf_cigi3_trajectory_definition_entity_id,
            { "Entity ID", "cigi.trajectory_def.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the entity for which the trajectory is defined", HFILL }
        },
        { &hf_cigi3_trajectory_definition_acceleration_x,
            { "Acceleration X (m/s^2)", "cigi.trajectory_def.acceleration_x",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the X component of the acceleration vector", HFILL }
        },
        { &hf_cigi3_trajectory_definition_acceleration_y,
            { "Acceleration Y (m/s^2)", "cigi.trajectory_def.acceleration_y",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Y component of the acceleration vector", HFILL }
        },
        { &hf_cigi3_trajectory_definition_acceleration_z,
            { "Acceleration Z (m/s^2)", "cigi.trajectory_def.acceleration_z",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Z component of the acceleration vector", HFILL }
        },
        { &hf_cigi3_trajectory_definition_retardation_rate,
            { "Retardation Rate (m/s^2)", "cigi.trajectory_def.retardation_rate",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the magnitude of an acceleration applied against the entity's instantaneous linear velocity vector", HFILL }
        },
        { &hf_cigi3_trajectory_definition_terminal_velocity,
            { "Terminal Velocity (m/s)", "cigi.trajectory_def.terminal_velocity",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the maximum velocity the entity can sustain", HFILL }
        },

        /* CIGI4 Acceleration Control */
        { &hf_cigi4_acceleration_control,
            { "Trajectory Definition", "cigi.acceleration_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Trajectory Definition Packet", HFILL }
        },
        { &hf_cigi4_acceleration_control_entity_id,
            { "Entity ID", "cigi.acceleration_control.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the entity for which the trajectory is defined", HFILL }
        },
        { &hf_cigi4_acceleration_control_articulated_part_id,
            { "Articulated Part ID", "cigi.acceleration_control.part_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the articulated part to which the acceleration may be applied", HFILL }
        },
        { &hf_cigi4_acceleration_control_apply_to_part,
            { "Apply to Articulated Part", "cigi.acceleration_control.apply_to_part",
                FT_BOOLEAN, 8, NULL, 0x01,
                "Indicates whether the acceleration may be applied to an articulated part or an entity", HFILL }
        },
        { &hf_cigi4_acceleration_control_coord_system,
            { "Sequence Direction", "cigi.acceleration_control.coord_system",
                FT_BOOLEAN, 8, TFS(&local_worldparent_tfs), 0x02,
                "Indicates the reference coordinate system to which the linear and angular accelerations may be applied", HFILL }
        },
        { &hf_cigi4_acceleration_control_acceleration_x,
            { "Acceleration X (m/s^2)", "cigi.acceleration_control.acceleration_x",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the X component of the acceleration vector", HFILL }
        },
        { &hf_cigi4_acceleration_control_acceleration_y,
            { "Acceleration Y (m/s^2)", "cigi.acceleration_control.acceleration_y",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Y component of the acceleration vector", HFILL }
        },
        { &hf_cigi4_acceleration_control_acceleration_z,
            { "Acceleration Z (m/s^2)", "cigi.acceleration_control.acceleration_z",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Z component of the acceleration vector", HFILL }
        },
        { &hf_cigi4_acceleration_control_acceleration_roll,
            { "Roll Angular Acceleration (deg/s^2)", "cigi.acceleration_control.acceleration_roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part submodel about its X axis after yaw and pitch have been applied.", HFILL }
        },
        { &hf_cigi4_acceleration_control_acceleration_pitch,
            { "Terminal Velocity (deg/s)", "cigi.acceleration_control.acceleration_pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part submodel about its Y axis after yaw and pitch have been applied", HFILL }
        },
        { &hf_cigi4_acceleration_control_acceleration_yaw,
            { "Terminal Velocity (deg/s)", "cigi.acceleration_control.acceleration_yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the angle of rotation of the articulated part submodel about its Z axis after yaw and pitch have been applied", HFILL }
        },

        /* CIGI2 Special Effect Definition */
        { &hf_cigi2_special_effect_definition,
            { "Special Effect Definition", "cigi.special_effect_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Special Effect Definition Packet", HFILL }
        },
        { &hf_cigi2_special_effect_definition_entity_id,
            { "Entity ID", "cigi.special_effect_def.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates which effect is being modified", HFILL }
        },
        { &hf_cigi2_special_effect_definition_seq_direction,
            { "Sequence Direction", "cigi.special_effect_def.seq_direction",
                FT_BOOLEAN, 8, TFS(&cigi2_special_effect_definition_seq_direction_tfs), 0x80,
                "Indicates whether the effect animation sequence should be sequence from beginning to end or vice versa", HFILL }
        },
        { &hf_cigi2_special_effect_definition_color_enable,
            { "Color Enable", "cigi.special_effect_def.color_enable",
                FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x40,
                "Indicates whether the red, green, and blue color values will be applied to the special effect", HFILL }
        },
        { &hf_cigi2_special_effect_definition_red,
            { "Red Color Value", "cigi.special_effect_def.red",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the red component of a color to be applied to the effect", HFILL }
        },
        { &hf_cigi2_special_effect_definition_green,
            { "Green Color Value", "cigi.special_effect_def.green",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the green component of a color to be applied to the effect", HFILL }
        },
        { &hf_cigi2_special_effect_definition_blue,
            { "Blue Color Value", "cigi.special_effect_def.blue",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the blue component of a color to be applied to the effect", HFILL }
        },
        { &hf_cigi2_special_effect_definition_x_scale,
            { "X Scale", "cigi.special_effect_def.x_scale",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies a scale factor to apply along the effect's X axis", HFILL }
        },
        { &hf_cigi2_special_effect_definition_y_scale,
            { "Y Scale", "cigi.special_effect_def.y_scale",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies a scale factor to apply along the effect's Y axis", HFILL }
        },
        { &hf_cigi2_special_effect_definition_z_scale,
            { "Z Scale", "cigi.special_effect_def.z_scale",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies a scale factor to apply along the effect's Z axis", HFILL }
        },
        { &hf_cigi2_special_effect_definition_time_scale,
            { "Time Scale", "cigi.special_effect_def.time_scale",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies a scale factor to apply to the time period for the effect's animation sequence", HFILL }
        },
        { &hf_cigi2_special_effect_definition_spare,
            { "Spare", "cigi.special_effect_def.spare",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi2_special_effect_definition_effect_count,
            { "Effect Count", "cigi.special_effect_def.effect_count",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates how many effects are contained within a single burst", HFILL }
        },
        { &hf_cigi2_special_effect_definition_separation,
            { "Separation (m)", "cigi.special_effect_def.separation",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the distance between particles within a burst", HFILL }
        },
        { &hf_cigi2_special_effect_definition_burst_interval,
            { "Burst Interval (s)", "cigi.special_effect_def.burst_interval",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the time between successive bursts", HFILL }
        },
        { &hf_cigi2_special_effect_definition_duration,
            { "Duration (s)", "cigi.special_effect_def.duration",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates how long an effect or sequence of burst will be active", HFILL }
        },

        /* CIGI2 View Definition */
        { &hf_cigi2_view_definition,
            { "View Definition", "cigi.view_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "View Definition Packet", HFILL }
        },
        { &hf_cigi2_view_definition_view_id,
            { "View ID", "cigi.view_def.view_id",
                FT_UINT8, BASE_DEC, NULL, 0xf8,
                "Specifies the view to which this packet should be applied", HFILL }
        },
        { &hf_cigi2_view_definition_view_group,
            { "View Group", "cigi.view_def.view_group",
                FT_UINT8, BASE_DEC, NULL, 0x07,
                "Specifies the view group to which the view is to be assigned", HFILL }
        },
        { &hf_cigi2_view_definition_view_type,
            { "View Type", "cigi.view_def.view_type",
                FT_UINT8, BASE_DEC, NULL, 0xe0,
                "Specifies the view type", HFILL }
        },
        { &hf_cigi2_view_definition_pixel_rep,
            { "Pixel Replication", "cigi.view_def.pixel_rep",
                FT_UINT8, BASE_DEC, VALS(cigi2_view_definition_pixel_rep_vals), 0x1c,
                "Specifies what pixel replication function should be applied to the view", HFILL }
        },
        { &hf_cigi2_view_definition_mirror,
            { "View Mirror", "cigi.view_def.mirror",
                FT_UINT8, BASE_DEC, VALS(cigi2_view_definition_mirror_vals), 0x03,
                "Specifies what mirroring function should be applied to the view", HFILL }
        },
        { &hf_cigi2_view_definition_tracker_assign,
            { "Tracker Assign", "cigi.view_def.tracker_assign",
                FT_BOOLEAN, 8, NULL, 0x80,
                "Specifies whether the view should be controlled by an external tracking device", HFILL }
        },
        { &hf_cigi2_view_definition_near_enable,
            { "Field of View Near Enable", "cigi.view_def.near_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40,
                "Identifies whether the field of view near value is manipulated from the Host", HFILL }
        },
        { &hf_cigi2_view_definition_far_enable,
            { "Field of View Far Enable", "cigi.view_def.far_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
                "Identifies whether the field of view far value is manipulated from the Host", HFILL }
        },
        { &hf_cigi2_view_definition_left_enable,
            { "Field of View Left Enable", "cigi.view_def.left_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Identifies whether the field of view left value is manipulated from the Host", HFILL }
        },
        { &hf_cigi2_view_definition_right_enable,
            { "Field of View Right Enable", "cigi.view_def.right_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Identifies whether the field of view right value is manipulated from the Host", HFILL }
        },
        { &hf_cigi2_view_definition_top_enable,
            { "Field of View Top Enable", "cigi.view_def.top_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
                "Identifies whether the field of view top value is manipulated from the Host", HFILL }
        },
        { &hf_cigi2_view_definition_bottom_enable,
            { "Field of View Bottom Enable", "cigi.view_def.bottom_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
                "Identifies whether the field of view bottom value is manipulated from the Host", HFILL }
        },
        { &hf_cigi2_view_definition_fov_near,
            { "Field of View Near (m)", "cigi.view_def.fov_near",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Defines the near clipping plane for the view", HFILL }
        },
        { &hf_cigi2_view_definition_fov_far,
            { "Field of View Far (m)", "cigi.view_def.fov_far",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Defines the far clipping plane for the view", HFILL }
        },
        { &hf_cigi2_view_definition_fov_left,
            { "Field of View Left (degrees)", "cigi.view_def.fov_left",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Defines the left clipping plane for the view", HFILL }
        },
        { &hf_cigi2_view_definition_fov_right,
            { "Field of View Right (degrees)", "cigi.view_def.fov_right",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Defines the right clipping plane for the view", HFILL }
        },
        { &hf_cigi2_view_definition_fov_top,
            { "Field of View Top (degrees)", "cigi.view_def.fov_top",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Defines the top clipping plane for the view", HFILL }
        },
        { &hf_cigi2_view_definition_fov_bottom,
            { "Field of View Bottom (degrees)", "cigi.view_def.fov_bottom",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Defines the bottom clipping plane for the view", HFILL }
        },

        /* CIGI3 View Definition */
        { &hf_cigi3_view_definition,
            { "View Definition", "cigi.view_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "View Definition Packet", HFILL }
        },
        { &hf_cigi3_view_definition_view_id,
            { "View ID", "cigi.view_def.view_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the view to which the data in this packet will be applied", HFILL }
        },
        { &hf_cigi3_view_definition_group_id,
            { "Group ID", "cigi.view_def.group_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the group to which the view is to be assigned", HFILL }
        },
        { &hf_cigi3_view_definition_near_enable,
            { "Near Enable", "cigi.view_def.near_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Specifies whether the near clipping plane will be set to the value of the Near parameter within this packet", HFILL }
        },
        { &hf_cigi3_view_definition_far_enable,
            { "Far Enable", "cigi.view_def.far_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
                "Specifies whether the far clipping plane will be set to the value of the Far parameter within this packet", HFILL }
        },
        { &hf_cigi3_view_definition_left_enable,
            { "Left Enable", "cigi.view_def.left_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
                "Specifies whether the left half-angle of the view frustum will be set according to the value of the Left parameter within this packet", HFILL }
        },
        { &hf_cigi3_view_definition_right_enable,
            { "Right Enable", "cigi.view_def.right_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Specifies whether the right half-angle of the view frustum will be set according to the value of the Right parameter within this packet", HFILL }
        },
        { &hf_cigi3_view_definition_top_enable,
            { "Top Enable", "cigi.view_def.top_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
                "Specifies whether the top half-angle of the view frustum will be set according to the value of the Top parameter within this packet", HFILL }
        },
        { &hf_cigi3_view_definition_bottom_enable,
            { "Bottom Enable", "cigi.view_def.bottom_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
                "Specifies whether the bottom half-angle of the view frustum will be set according to the value of the Bottom parameter within this packet", HFILL }
        },
        { &hf_cigi3_view_definition_mirror_mode,
            { "Mirror Mode", "cigi.view_def.mirror_mode",
                FT_UINT8, BASE_DEC, VALS(cigi3_view_definition_mirror_mode_vals), 0xc0,
                "Specifies the mirroring function to be performed on the view", HFILL }
        },
        { &hf_cigi3_view_definition_pixel_replication,
            { "Pixel Replication Mode", "cigi.view_def.pixel_replication",
                FT_UINT8, BASE_DEC, VALS(cigi3_view_definition_pixel_replication_vals), 0x07,
                "Specifies the pixel replication function to be performed on the view", HFILL }
        },
        { &hf_cigi3_view_definition_projection_type,
            { "Projection Type", "cigi.view_def.projection_type",
                FT_BOOLEAN, 8, TFS(&cigi3_view_definition_projection_type_tfs), 0x08,
                "Specifies whether the view projection should be perspective or orthographic parallel", HFILL }
        },
        { &hf_cigi3_view_definition_reorder,
            { "Reorder", "cigi.view_def.reorder",
                FT_BOOLEAN, 8, TFS(&cigi3_view_definition_reorder_tfs), 0x10,
                "Specifies whether the view should be moved to the top of any overlapping views", HFILL }
        },
        { &hf_cigi3_view_definition_view_type,
            { "View Type", "cigi.view_def.view_type",
                FT_UINT8, BASE_DEC, NULL, 0xe0,
                "Specifies an IG-defined type for the indicated view", HFILL }
        },
        { &hf_cigi3_view_definition_near,
            { "Near (m)", "cigi.view_def.near",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the position of the view's near clipping plane", HFILL }
        },
        { &hf_cigi3_view_definition_far,
            { "Far (m)", "cigi.view_def.far",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the position of the view's far clipping plane", HFILL }
        },
        { &hf_cigi3_view_definition_left,
            { "Left (degrees)", "cigi.view_def.left",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the left half-angle of the view frustum", HFILL }
        },
        { &hf_cigi3_view_definition_right,
            { "Right (degrees)", "cigi.view_def.right",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the right half-angle of the view frustum", HFILL }
        },
        { &hf_cigi3_view_definition_top,
            { "Top (degrees)", "cigi.view_def.top",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the top half-angle of the view frustum", HFILL }
        },
        { &hf_cigi3_view_definition_bottom,
            { "Bottom (degrees)", "cigi.view_def.bottom",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the bottom half-angle of the view frustum", HFILL }
        },

        /* CIGI4 View Definition */

        /* CIGI2 Collision Detection Segment Definition */
        { &hf_cigi2_collision_detection_segment_definition,
            { "Collision Detection Segment Definition", "cigi.coll_det_seg_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Collision Detection Segment Definition Packet", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_definition_entity_id,
            { "Entity ID", "cigi.coll_det_seg_def.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity to which this collision detection definition is assigned", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_definition_segment_enable,
            { "Segment Enable", "cigi.coll_det_seg_def.segment_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
                "Indicates whether the defined segment is enabled for collision testing", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_definition_segment_id,
            { "Segment ID", "cigi.coll_det_seg_def.segment_id",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                "Indicates which segment is being uniquely defined for the given entity", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_definition_collision_mask,
            { "Collision Mask", "cigi.coll_det_seg_def.collision_mask",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Indicates which environment features will be included in or excluded from consideration for collision detection testing", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_definition_x_start,
            { "Segment X Start (m)", "cigi.coll_det_seg_def.x_start",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the starting point of the collision segment in the X-axis with respect to the entity's reference point", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_definition_y_start,
            { "Segment Y Start (m)", "cigi.coll_det_seg_def.y_start",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the starting point of the collision segment in the Y-axis with respect to the entity's reference point", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_definition_z_start,
            { "Segment Z Start (m)", "cigi.coll_det_seg_def.z_start",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the starting point of the collision segment in the Z-axis with respect to the entity's reference point", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_definition_x_end,
            { "Segment X End (m)", "cigi.coll_det_seg_def.x_end",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the ending point of the collision segment in the X-axis with respect to the entity's reference point", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_definition_y_end,
            { "Segment Y End (m)", "cigi.coll_det_seg_def.y_end",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the ending point of the collision segment in the Y-axis with respect to the entity's reference point", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_definition_z_end,
            { "Segment Z End (m)", "cigi.coll_det_seg_def.z_end",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the ending point of the collision segment in the Z-axis with respect to the entity's reference point", HFILL }
        },

        /* CIGI3 Collision Detection Segment Definition */
        { &hf_cigi3_collision_detection_segment_definition,
            { "Collision Detection Segment Definition", "cigi.coll_det_seg_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Collision Detection Segment Definition Packet", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_definition_entity_id,
            { "Entity ID", "cigi.coll_det_seg_def.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity for which the segment is defined", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_definition_segment_id,
            { "Segment ID", "cigi.coll_det_seg_def.segment_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the ID of the segment", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_definition_segment_enable,
            { "Segment Enable", "cigi.coll_det_seg_def.segment_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Specifies whether the segment is enabled or disabled", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_definition_x1,
            { "X1 (m)", "cigi.coll_det_seg_def.x1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the X offset of one endpoint of the collision segment", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_definition_y1,
            { "Y1 (m)", "cigi.coll_det_seg_def.y1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Y offset of one endpoint of the collision segment", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_definition_z1,
            { "Z1 (m)", "cigi.coll_det_seg_def.z1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Z offset of one endpoint of the collision segment", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_definition_x2,
            { "X2 (m)", "cigi.coll_det_seg_def.x2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the X offset of one endpoint of the collision segment", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_definition_y2,
            { "Y2 (m)", "cigi.coll_det_seg_def.y2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Y offset of one endpoint of the collision segment", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_definition_z2,
            { "Z2 (m)", "cigi.coll_det_seg_def.z2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Z offset of one endpoint of the collision segment", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_definition_material_mask,
            { "Material Mask", "cigi.coll_det_seg_def.material_mask",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Specifies the environmental and cultural features to be included in or excluded from consideration for collision testing", HFILL }
        },

        /* CIGI4 Collision Detection Segment Definition */

        /* CIGI2 Collision Detection Volume Definition */
        { &hf_cigi2_collision_detection_volume_definition,
            { "Collision Detection Volume Definition", "cigi.coll_det_vol_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Collision Detection Volume Definition Packet", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_definition_entity_id,
            { "Entity ID", "cigi.coll_det_vol_def.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity to which this collision detection definition is assigned", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_definition_volume_enable,
            { "Volume Enable", "cigi.coll_det_vol_def.volume_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
                "Indicates whether the defined volume is enabled for collision testing", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_definition_volume_id,
            { "Volume ID", "cigi.coll_det_vol_def.volume_id",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                "Indicates which volume is being uniquely defined for a given entity", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_definition_x_offset,
            { "Centroid X Offset (m)", "cigi.coll_det_vol_def.x_offset",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the offset of the volume's centroid along the X axis with respect to the entity's reference point", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_definition_y_offset,
            { "Centroid Y Offset (m)", "cigi.coll_det_vol_def.y_offset",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the offset of the volume's centroid along the Y axis with respect to the entity's reference point", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_definition_z_offset,
            { "Centroid Z Offset (m)", "cigi.coll_det_vol_def.z_offset",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the offset of the volume's centroid along the Z axis with respect to the entity's reference point", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_definition_height,
            { "Height (m)", "cigi.coll_det_vol_def.height",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the height of the volume", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_definition_width,
            { "Width (m)", "cigi.coll_det_vol_def.width",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the width of the volume", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_definition_depth,
            { "Depth (m)", "cigi.coll_det_vol_def.depth",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the depth of the volume", HFILL }
        },

        /* CIGI3 Collision Detection Volume Definition */
        { &hf_cigi3_collision_detection_volume_definition,
            { "Collision Detection Volume Definition", "cigi.coll_det_vol_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Collision Detection Volume Definition Packet", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_entity_id,
            { "Entity ID", "cigi.coll_det_vol_def.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity for which the volume is defined", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_volume_id,
            { "Volume ID", "cigi.coll_det_vol_def.volume_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the ID of the volume", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_volume_enable,
            { "Volume Enable", "cigi.coll_det_vol_def.volume_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
                "Specifies whether the volume is enabled or disabled", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_volume_type,
            { "Volume Type", "cigi.coll_det_vol_def.volume_type",
                FT_BOOLEAN, 8, TFS(&cigi3_collision_detection_volume_definition_volume_type_tfs), 0x02,
                "Specified whether the volume is spherical or cuboid", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_x,
            { "X (m)", "cigi.coll_det_vol_def.x",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the X offset of the center of the volume", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_y,
            { "Y (m)", "cigi.coll_det_vol_def.y",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Y offset of the center of the volume", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_z,
            { "Z (m)", "cigi.coll_det_vol_def.z",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Z offset of the center of the volume", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_radius_height,
            { "Radius (m)/Height (m)", "cigi.coll_det_vol_def.radius_height",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius of the sphere or specifies the length of the cuboid along its Z axis", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_width,
            { "Width (m)", "cigi.coll_det_vol_def.width",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the length of the cuboid along its Y axis", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_depth,
            { "Depth (m)", "cigi.coll_det_vol_def.depth",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the length of the cuboid along its X axis", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_roll,
            { "Roll (degrees)", "cigi.coll_det_vol_def.roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the roll of the cuboid with respect to the entity's coordinate system", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_pitch,
            { "Pitch (degrees)", "cigi.coll_det_vol_def.pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the pitch of the cuboid with respect to the entity's coordinate system", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_definition_yaw,
            { "Yaw (degrees)", "cigi.coll_det_vol_def.yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the yaw of the cuboid with respect to the entity's coordinate system", HFILL }
        },

        /* CIGI4 Collision Detection Volume Definition */

        /* CIGI2 Height Above Terrain Request */
        { &hf_cigi2_height_above_terrain_request,
            { "Height Above Terrain Request", "cigi.hat_request",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Height Above Terrain Request Packet", HFILL }
        },
        { &hf_cigi2_height_above_terrain_request_hat_id,
            { "HAT ID", "cigi.hat_request.hat_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the HAT request", HFILL }
        },
        { &hf_cigi2_height_above_terrain_request_alt,
            { "Altitude (m)", "cigi.hat_request.alt",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the altitude from which the HAT request is being made", HFILL }
        },
        { &hf_cigi2_height_above_terrain_request_lat,
            { "Latitude (degrees)", "cigi.hat_request.lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the latitudinal position from which the HAT request is being made", HFILL }
        },
        { &hf_cigi2_height_above_terrain_request_lon,
            { "Longitude (degrees)", "cigi.hat_request.lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the longitudinal position from which the HAT request is being made", HFILL }
        },

        /* CIGI2 Line of Sight Occult Request */
        { &hf_cigi2_line_of_sight_occult_request,
            { "Line of Sight Occult Request", "cigi.los_occult_request",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Line of Sight Occult Request Packet", HFILL }
        },
        { &hf_cigi2_line_of_sight_occult_request_los_id,
            { "LOS ID", "cigi.los_occult_request.los_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the LOS request", HFILL }
        },
        { &hf_cigi2_line_of_sight_occult_request_source_alt,
            { "Source Altitude (m)", "cigi.los_occult_request.source_alt",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the altitude of the source point for the LOS request segment", HFILL }
        },
        { &hf_cigi2_line_of_sight_occult_request_source_lat,
            { "Source Latitude (degrees)", "cigi.los_occult_request.source_lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the latitudinal position of the source point for the LOS request segment", HFILL }
        },
        { &hf_cigi2_line_of_sight_occult_request_source_lon,
            { "Source Longitude (degrees)", "cigi.los_occult_request.source_lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the longitudinal position of the source point for the LOS request segment", HFILL }
        },
        { &hf_cigi2_line_of_sight_occult_request_dest_alt,
            { "Destination Altitude (m)", "cigi.los_occult_request.dest_alt",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the altitude of the destination point for the LOS request segment", HFILL }
        },
        { &hf_cigi2_line_of_sight_occult_request_dest_lat,
            { "Destination Latitude (degrees)", "cigi.los_occult_request.dest_lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the latitudinal position for the destination point for the LOS request segment", HFILL }
        },
        { &hf_cigi2_line_of_sight_occult_request_dest_lon,
            { "Destination Longitude (degrees)", "cigi.los_occult_request.dest_lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the longitudinal position of the destination point for the LOS request segment", HFILL }
        },

        /* CIGI2 Line of Sight Range Request */
        { &hf_cigi2_line_of_sight_range_request,
            { "Line of Sight Range Request", "cigi.los_range_request",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Line of Sight Range Request Packet", HFILL }
        },
        { &hf_cigi2_line_of_sight_range_request_los_id,
            { "LOS ID", "cigi.los_range_request.los_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the LOS request", HFILL }
        },
        { &hf_cigi2_line_of_sight_range_request_azimuth,
            { "Azimuth (degrees)", "cigi.los_range_request.azimuth",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the azimuth of the LOS vector", HFILL }
        },
        { &hf_cigi2_line_of_sight_range_request_elevation,
            { "Elevation (degrees)", "cigi.los_range_request.elevation",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the elevation for the LOS vector", HFILL }
        },
        { &hf_cigi2_line_of_sight_range_request_min_range,
            { "Minimum Range (m)", "cigi.los_range_request.min_range",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the distance from the source position specified in this data packet to a point along the LOS vector where intersection testing will begin", HFILL }
        },
        { &hf_cigi2_line_of_sight_range_request_max_range,
            { "Maximum Range (m)", "cigi.los_range_request.max_range",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the maximum extent from the source position specified in this data packet to a point along the LOS vector where intersection testing will end", HFILL }
        },
        { &hf_cigi2_line_of_sight_range_request_source_alt,
            { "Source Altitude (m)", "cigi.los_range_request.source_alt",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the altitude of the source point of the LOS request vector", HFILL }
        },
        { &hf_cigi2_line_of_sight_range_request_source_lat,
            { "Source Latitude (degrees)", "cigi.los_range_request.source_lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the latitudinal position of the source point of the LOS request vector", HFILL }
        },
        { &hf_cigi2_line_of_sight_range_request_source_lon,
            { "Source Longitude (degrees)", "cigi.los_range_request.source_lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the longitudinal position of the source point of the LOS request vector", HFILL }
        },

        /* CIGI2 Height of Terrain Request */
        { &hf_cigi2_height_of_terrain_request,
            { "Height of Terrain Request", "cigi.hot_request",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Height of Terrain Request Packet", HFILL }
        },
        { &hf_cigi2_height_of_terrain_request_hot_id,
            { "HOT ID", "cigi.hot_request.hot_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the HOT request", HFILL }
        },
        { &hf_cigi2_height_of_terrain_request_lat,
            { "Latitude (degrees)", "cigi.hot_request.lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the latitudinal position from which the HOT request is made", HFILL }
        },
        { &hf_cigi2_height_of_terrain_request_lon,
            { "Longitude (degrees)", "cigi.hot_request.lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the longitudinal position from which the HOT request is made", HFILL }
        },

        /* CIGI3 HAT/HOT Request */
        { &hf_cigi3_hat_hot_request,
            { "HAT/HOT Request", "cigi.hat_hot_request",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "HAT/HOT Request Packet", HFILL }
        },
        { &hf_cigi3_hat_hot_request_hat_hot_id,
            { "HAT/HOT ID", "cigi.hat_hot_request.hat_hot_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the HAT/HOT request", HFILL }
        },
        { &hf_cigi3_hat_hot_request_type,
            { "Request Type", "cigi.hat_hot_request.type",
                FT_UINT8, BASE_DEC, VALS(cigi3_hat_hot_request_type_vals), 0x03,
                "Determines the type of response packet the IG should return for this packet", HFILL }
        },
        { &hf_cigi3_hat_hot_request_coordinate_system,
            { "Coordinate System", "cigi.hat_hot_request.coordinate_system",
                FT_BOOLEAN, 8, TFS(&entity_geodetic_tfs), 0x04,
                "Specifies the coordinate system within which the test point is defined", HFILL }
        },
        { &hf_cigi3_hat_hot_request_entity_id,
            { "Entity ID", "cigi.hat_hot_request.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity relative to which the test point is defined", HFILL }
        },
        { &hf_cigi3_hat_hot_request_lat_xoff,
            { "Latitude (degrees)/X Offset (m)", "cigi.hat_hot_request.lat_xoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the latitude from which the HAT/HOT request is being made or specifies the X offset of the point from which the HAT/HOT request is being made", HFILL }
        },
        { &hf_cigi3_hat_hot_request_lon_yoff,
            { "Longitude (degrees)/Y Offset (m)", "cigi.hat_hot_request.lon_yoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the longitude from which the HAT/HOT request is being made or specifies the Y offset of the point from which the HAT/HOT request is being made", HFILL }
        },
        { &hf_cigi3_hat_hot_request_alt_zoff,
            { "Altitude (m)/Z Offset (m)", "cigi.hat_hot_request.alt_zoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the altitude from which the HAT/HOT request is being made or specifies the Z offset of the point from which the HAT/HOT request is being made", HFILL }
        },

        /* CIGI3_2 HAT/HOT Request */
        { &hf_cigi3_2_hat_hot_request_update_period,
            { "Update Period", "cigi.hat_hot_request.update_period",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies interval between successive responses to this request. A zero indicates one responses a value n > 0 the IG should respond every nth frame", HFILL }
        },

        /* CIGI4 HAT/HOT Request */
        { &hf_cigi4_hat_hot_request_flags,
            { "Request Flags", "cigi.hat_hot_request.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },

        /* CIGI3 Line of Sight Segment Request */
        { &hf_cigi3_line_of_sight_segment_request,
            { "Line of Sight Segment Request", "cigi.los_segment_request",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Line of Sight Segment Request Packet", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_los_id,
            { "LOS ID", "cigi.los_segment_request.los_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the LOS request", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_type,
            { "Request Type", "cigi.los_segment_request.type",
                FT_BOOLEAN, 8, TFS(&extended_normal_tfs), 0x01,
                "Determines what type of response the IG should return for this request", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_source_coord,
            { "Source Point Coordinate System", "cigi.los_segment_request.source_coord",
                FT_BOOLEAN, 8, TFS(&entity_geodetic_tfs), 0x02,
                "Indicates the coordinate system relative to which the test segment source endpoint is specified", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_destination_coord,
            { "Destination Point Coordinate System", "cigi.los_segment_request.destination_coord",
                FT_BOOLEAN, 8, TFS(&entity_geodetic_tfs), 0x04,
                "Indicates the coordinate system relative to which the test segment destination endpoint is specified", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_response_coord,
            { "Response Coordinate System", "cigi.los_segment_request.response_coord",
                FT_BOOLEAN, 8, TFS(&entity_geodetic_tfs), 0x08,
                "Specifies the coordinate system to be used in the response", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_alpha_threshold,
            { "Alpha Threshold", "cigi.los_segment_request.alpha_threshold",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the minimum alpha value a surface may have for an LOS response to be generated", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_source_entity_id,
            { "Source Entity ID", "cigi.los_segment_request.source_entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity relative to which the test segment endpoints are defined", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_source_lat_xoff,
            { "Source Latitude (degrees)/Source X Offset (m)", "cigi.los_segment_request.source_lat_xoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the latitude of the source endpoint of the LOS test segment or specifies the X offset of the source endpoint of the LOS test segment", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_source_lon_yoff,
            { "Source Longitude (degrees)/Source Y Offset (m)", "cigi.los_segment_request.source_lon_yoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the longitude of the source endpoint of the LOS test segment or specifies the Y offset of the source endpoint of the LOS test segment", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_source_alt_zoff,
            { "Source Altitude (m)/Source Z Offset (m)", "cigi.los_segment_request.source_alt_zoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the altitude of the source endpoint of the LOS test segment or specifies the Z offset of the source endpoint of the LOS test segment", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_destination_lat_xoff,
            { "Destination Latitude (degrees)/ Destination X Offset (m)", "cigi.los_segment_request.destination_lat_xoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the latitude of the destination endpoint of the LOS test segment or specifies the X offset of the destination endpoint of the LOS test segment", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_destination_lon_yoff,
            { "Destination Longitude (degrees)/Destination Y Offset (m)", "cigi.los_segment_request.destination_lon_yoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the longitude of the destination endpoint of the LOS test segment or specifies the Y offset of the destination endpoint of the LOS test segment", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_destination_alt_zoff,
            { "Destination Altitude (m)/ Destination Z Offset (m)", "cigi.los_segment_request.destination_alt_zoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the altitude of the destination endpoint of the LOS test segment or specifies the Z offset of the destination endpoint of the LOS test segment", HFILL }
        },
        { &hf_cigi3_line_of_sight_segment_request_material_mask,
            { "Material Mask", "cigi.los_segment_request.material_mask",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Specifies the environmental and cultural features to be included in or excluded from consideration for the LOS segment testing", HFILL }
        },

        /* CIGI3_2 Line of Sight Segment Request */
        { &hf_cigi3_2_line_of_sight_segment_request_destination_entity_id_valid,
            { "Destination Entity ID Valid", "cigi.los_segment_request.destination_entity_id_valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x10,
                "Destination Entity ID is valid.", HFILL }
        },
        { &hf_cigi3_2_line_of_sight_segment_request_update_period,
            { "Update Period", "cigi.los_segment_request.update_period",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies interval between successive responses to this request. A zero indicates one responses a value n > 0 the IG should respond every nth frame", HFILL }
        },
        { &hf_cigi3_2_line_of_sight_segment_request_destination_entity_id,
            { "Destination Entity ID", "cigi.los_segment_request.destination_entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity with respect to which the Destination X Offset, Y Offset, and Destination Z Offset parameters are specified", HFILL }
        },

        /* CIGI4 Line of Sight Segment Request */

        /* CIGI3 Line of Sight Vector Request */
        { &hf_cigi3_line_of_sight_vector_request,
            { "Line of Sight Vector Request", "cigi.los_vector_request",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Line of Sight Vector Request Packet", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_los_id,
            { "LOS ID", "cigi.los_vector_request.los_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the LOS request", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_type,
            { "Request Type", "cigi.los_vector_request.type",
                FT_BOOLEAN, 8, TFS(&extended_normal_tfs), 0x01,
                "Determines what type of response the IG should return for this request", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_source_coord,
            { "Source Point Coordinate System", "cigi.los_vector_request.source_coord",
                FT_BOOLEAN, 8, TFS(&entity_geodetic_tfs), 0x02,
                "Indicates the coordinate system relative to which the test vector source point is specified", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_response_coord,
            { "Response Coordinate System", "cigi.los_vector_request.response_coord",
                FT_BOOLEAN, 8, TFS(&entity_geodetic_tfs), 0x04,
                "Specifies the coordinate system to be used in the response", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_alpha,
            { "Alpha Threshold", "cigi.los_vector_request.alpha",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the minimum alpha value a surface may have for an LOS response to be generated", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_entity_id,
            { "Entity ID", "cigi.los_vector_request.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity relative to which the test segment endpoints are defined", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_azimuth,
            { "Azimuth (degrees)", "cigi.los_vector_request.azimuth",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the horizontal angle of the LOS test vector", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_elevation,
            { "Elevation (degrees)", "cigi.los_vector_request.elevation",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the vertical angle of the LOS test vector", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_min_range,
            { "Minimum Range (m)", "cigi.los_vector_request.min_range",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the minimum range along the LOS test vector at which intersection testing should occur", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_max_range,
            { "Maximum Range (m)", "cigi.los_vector_request.max_range",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the maximum range along the LOS test vector at which intersection testing should occur", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_source_lat_xoff,
            { "Source Latitude (degrees)/Source X Offset (m)", "cigi.los_vector_request.source_lat_xoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the latitude of the source point of the LOS test vector", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_source_lon_yoff,
            { "Source Longitude (degrees)/Source Y Offset (m)", "cigi.los_vector_request.source_lon_yoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the longitude of the source point of the LOS test vector", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_source_alt_zoff,
            { "Source Altitude (m)/Source Z Offset (m)", "cigi.los_vector_request.source_alt_zoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the altitude of the source point of the LOS test vector or specifies the Z offset of the source point of the LOS test vector", HFILL }
        },
        { &hf_cigi3_line_of_sight_vector_request_material_mask,
            { "Material Mask", "cigi.los_vector_request.material_mask",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Specifies the environmental and cultural features to be included in LOS segment testing", HFILL }
        },

        /* CIGI3_2 Line of Sight Vector Request */
        { &hf_cigi3_2_line_of_sight_vector_request_update_period,
            { "Update Period", "cigi.los_vector_request.update_period",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies interval between successive responses to this request. A zero indicates one responses a value n > 0 the IG should respond every nth frame", HFILL }
        },


        /* CIGI4 Line of Sight Vector Request */

        /* CIGI3 Position Request */
        { &hf_cigi3_position_request,
            { "Position Request", "cigi.pos_request",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Position Request Packet", HFILL }
        },
        { &hf_cigi3_position_request_object_id,
            { "Object ID", "cigi.pos_request.object_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the entity, view, view group, or motion tracking device whose position is being requested", HFILL }
        },
        { &hf_cigi3_position_request_part_id,
            { "Articulated Part ID", "cigi.pos_request.part_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the articulated part whose position is being requested", HFILL }
        },
        { &hf_cigi3_position_request_update_mode,
            { "Update Mode", "cigi.pos_request.update_mode",
                FT_BOOLEAN, 8, TFS(&cigi3_position_request_update_mode_tfs), 0x01,
                "Specifies whether the IG should report the position of the requested object each frame", HFILL }
        },
        { &hf_cigi3_position_request_object_class,
            { "Object Class", "cigi.pos_request.object_class",
                FT_UINT8, BASE_DEC, VALS(cigi3_position_request_object_class_vals), 0x0e,
                "Specifies the type of object whose position is being requested", HFILL }
        },
        { &hf_cigi3_position_request_coord_system,
            { "Coordinate System", "cigi.pos_request.coord_system",
                FT_UINT8, BASE_DEC, VALS(cigi3_position_request_coord_system_vals), 0x30,
                "Specifies the desired coordinate system relative to which the position and orientation should be given", HFILL }
        },

        /* CIGI4 Position Request */

        /* CIGI3 Environmental Conditions Request */
        { &hf_cigi3_environmental_conditions_request,
            { "Environmental Conditions Request", "cigi.env_cond_request",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Environmental Conditions Request Packet", HFILL }
        },
        { &hf_cigi3_environmental_conditions_request_type,
            { "Request Type", "cigi.env_cond_request.type",
                FT_UINT8, BASE_DEC, VALS(cigi3_environmental_conditions_request_type_vals), 0x0f,
                "Specifies the desired response type for the request", HFILL }
        },
        { &hf_cigi3_environmental_conditions_request_id,
            { "Request ID", "cigi.env_cond_request.id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the environmental conditions request", HFILL }
        },
        { &hf_cigi3_environmental_conditions_request_lat,
            { "Latitude (degrees)", "cigi.env_cond_request.lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the geodetic latitude at which the environmental state is requested", HFILL }
        },
        { &hf_cigi3_environmental_conditions_request_lon,
            { "Longitude (degrees)", "cigi.env_cond_request.lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the geodetic longitude at which the environmental state is requested", HFILL }
        },
        { &hf_cigi3_environmental_conditions_request_alt,
            { "Altitude (m)", "cigi.env_cond_request.alt",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the geodetic altitude at which the environmental state is requested", HFILL }
        },

        /* CIGI4 Environmental Conditions Request */

        /* CIGI3_3 Symbol Surface Definition */
        { &hf_cigi3_3_symbol_surface_definition,
            { "Symbol Surface Definition", "cigi.symbl_srfc_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Symbol Surface Definition Packet", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_surface_id,
            { "Surface ID", "cigi.symbl_srfc_def.surface_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the symbol surface to which this packet is applied", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_surface_state,
            { "Surface State", "cigi.symbl_srfc_def.surface_state",
                FT_BOOLEAN, 8, TFS(&cigi3_3_symbol_surface_definition_surface_state_tfs), 0x01,
                "Specifies whether the symbol surface should be active or destroyed", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_attach_type,
            { "Attach Type", "cigi.symbl_srfc_def.attach_type",
                FT_BOOLEAN, 8, TFS(&cigi3_3_symbol_surface_definition_attach_type_tfs), 0x02,
                "Specifies whether the surface should be attached to an entity or view", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_billboard,
            { "Billboard", "cigi.symbl_srfc_def.billboard",
                FT_BOOLEAN, 8, TFS(&cigi3_3_symbol_surface_definition_billboard_tfs), 0x04,
                "Specifies whether the surface is treated as a billboard", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_perspective_growth_enable,
            { "Perspective Growth Enable", "cigi.symbl_srfc_def.perspective_growth_enable",
                FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
                "Specifies whether the surface appears to maintain a constant size or has perspective growth", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_entity_view_id,
            { "Entity ID/View ID", "cigi.symbl_srfc_def.entity_view_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the entity or view to which this symbol surface is attached", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_xoff_left,
            { "X Offset (m)/Left", "cigi.symbl_srfc_def.xoff_left",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the x offset or leftmost boundary for the symbol surface", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_yoff_right,
            { "Y Offset (m)/Right", "cigi.symbl_srfc_def.yoff_right",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the y offset or rightmost boundary for the symbol surface", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_zoff_top,
            { "Z Offset (m)/Top", "cigi.symbl_srfc_def.zoff_top",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the z offset or topmost boundary for the symbol surface", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_yaw_bottom,
            { "Yaw (degrees)/Bottom", "cigi.symbl_srfc_def.yaw_bottom",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation about the surface's Z axis or bottommost boundary for the symbol surface", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_pitch,
            { "Pitch (degrees)", "cigi.symbl_srfc_def.pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation about the surface's Y axis", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_roll,
            { "Roll (degrees)", "cigi.symbl_srfc_def.roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation about the surface's X axis", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_width,
            { "Width (m/degrees)", "cigi.symbl_srfc_def.width",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the width of the symbol surface", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_height,
            { "Height (m/degrees)", "cigi.symbl_srfc_def.height",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the height of the symbol surface", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_min_u,
            { "Min U (surface horizontal units)", "cigi.symbl_srfc_def.min_u",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the minimum U coordinate of the symbol surface's viewable area", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_max_u,
            { "Max U (surface horizontal units)", "cigi.symbl_srfc_def.max_u",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the maximum U coordinate of the symbol surface's viewable area", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_min_v,
            { "Min V (surface vertical units)", "cigi.symbl_srfc_def.min_v",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the minimum V coordinate of the symbol surface's viewable area", HFILL }
        },
        { &hf_cigi3_3_symbol_surface_definition_max_v,
            { "Max V (surface vertical units)", "cigi.symbl_srfc_def.max_v",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the maximum V coordinate of the symbol surface's viewable area", HFILL }
        },


        /* CIGI4 Symbol Surface Definition */

        /* CIGI3_3 Symbol Text Definition */
        { &hf_cigi3_3_symbol_text_definition,
            { "Symbol Text Definition", "cigi.symbol_text_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Symbol Text Definition Packet", HFILL }
        },
        { &hf_cigi3_3_symbol_text_definition_symbol_id,
            { "Symbol ID", "cigi.symbol_text_def.symbol_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the identifier of the symbol that is being defined", HFILL }
        },
        { &hf_cigi3_3_symbol_text_definition_alignment,
            { "Alignment", "cigi.symbol_text_def.alignment",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_symbol_text_definition_alignment_vals), 0x0f,
                "Specifies the position of the symbol's reference point", HFILL }
        },
        { &hf_cigi3_3_symbol_text_definition_orientation,
            { "Orientation", "cigi.symbol_text_def.orientation",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_symbol_text_definition_orientation_vals), 0x30,
                "Specifies the orientation of the text", HFILL }
        },
        { &hf_cigi3_3_symbol_text_definition_font_ident,
            { "Font ID", "cigi.symbol_text_def.font_ident",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_symbol_text_definition_font_ident_vals), 0x0,
                "Specifies the font to be used", HFILL }
        },
        { &hf_cigi3_3_symbol_text_definition_font_size,
            { "Font Size", "cigi.symbol_text_def.font_size",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the font size", HFILL }
        },
        { &hf_cigi3_3_symbol_text_definition_text,
            { "Text", "cigi.symbol_text_def.text",
                FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
                "Symbol text", HFILL }
        },

        /* CIGI4 Symbol Text Definition */

        /* CIGI3_3 Symbol Circle Definition */
        { &hf_cigi3_3_symbol_circle_definition,
            { "Symbol Circle Definition", "cigi.symbol_circle_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Symbol Circle Definition Packet", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_symbol_id,
            { "Symbol ID", "cigi.symbol_circle_def.symbol_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the identifier of the symbol that is being defined", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_drawing_style,
            { "Drawing Style", "cigi.symbol_circle_def.drawing_style",
                FT_BOOLEAN, 8, TFS(&cigi3_3_symbol_circle_definition_drawing_style_tfs), 0x01,
                "Specifies whether the circles and arcs are curved lines or filled areas", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_stipple_pattern,
            { "Stipple Pattern", "cigi.symbol_circle_def.stipple_pattern",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "Specifies the dash pattern used", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_line_width,
            { "Line Width (scaled symbol surface units)", "cigi.symbol_circle_def.line_width",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the thickness of the line", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_stipple_pattern_length,
            { "Stipple Pattern Length (scaled symbol surface units)", "cigi.symbol_circle_def.stipple_pattern_length",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the length of one complete repetition of the stipple pattern", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_u[0],
            { "Center U 1 (scaled symbol surface units)", "cigi.symbol_circle_def.center_u1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_v[0],
            { "Center V 1 (scaled symbol surface units)", "cigi.symbol_circle_def.center_v1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_radius[0],
            { "Radius 1 (scaled symbol surface units)", "cigi.symbol_circle_def.radius1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_inner_radius[0],
            { "Inner Radius 1 (scaled symbol surface units)", "cigi.symbol_circle_def.inner_radius1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_start_angle[0],
            { "Start Angle 1 (degrees)", "cigi.symbol_circle_def.start_angle1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_end_angle[0],
            { "End Angle 1 (degrees)", "cigi.symbol_circle_def.end_angle1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_u[1],
            { "Center U 2 (scaled symbol surface units)", "cigi.symbol_circle_def.center_u2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_v[1],
            { "Center V 2 (scaled symbol surface units)", "cigi.symbol_circle_def.center_v2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_radius[1],
            { "Radius 2 (scaled symbol surface units)", "cigi.symbol_circle_def.radius2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_inner_radius[1],
            { "Inner Radius 2 (scaled symbol surface units)", "cigi.symbol_circle_def.inner_radius2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_start_angle[1],
            { "Start Angle 2 (degrees)", "cigi.symbol_circle_def.start_angle2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_end_angle[1],
            { "End Angle 2 (degrees)", "cigi.symbol_circle_def.end_angle2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_u[2],
            { "Center U 3 (scaled symbol surface units)", "cigi.symbol_circle_def.center_u3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_v[2],
            { "Center V 3 (scaled symbol surface units)", "cigi.symbol_circle_def.center_v3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_radius[2],
            { "Radius 3 (scaled symbol surface units)", "cigi.symbol_circle_def.radius3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_inner_radius[2],
            { "Inner Radius 3 (scaled symbol surface units)", "cigi.symbol_circle_def.inner_radius3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_start_angle[2],
            { "Start Angle 3 (degrees)", "cigi.symbol_circle_def.start_angle3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_end_angle[2],
            { "End Angle 3 (degrees)", "cigi.symbol_circle_def.end_angle3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_u[3],
            { "Center U 4 (scaled symbol surface units)", "cigi.symbol_circle_def.center_u4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_v[3],
            { "Center V 4 (scaled symbol surface units)", "cigi.symbol_circle_def.center_v4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_radius[3],
            { "Radius 4 (scaled symbol surface units)", "cigi.symbol_circle_def.radius4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_inner_radius[3],
            { "Inner Radius 4 (scaled symbol surface units)", "cigi.symbol_circle_def.inner_radius4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_start_angle[3],
            { "Start Angle 4 (degrees)", "cigi.symbol_circle_def.start_angle4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_end_angle[3],
            { "End Angle 4 (degrees)", "cigi.symbol_circle_def.end_angle4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_u[4],
            { "Center U 5 (scaled symbol surface units)", "cigi.symbol_circle_def.center_u5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_v[4],
            { "Center V 5 (scaled symbol surface units)", "cigi.symbol_circle_def.center_v5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_radius[4],
            { "Radius 5 (scaled symbol surface units)", "cigi.symbol_circle_def.radius5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_inner_radius[4],
            { "Inner Radius 5 (scaled symbol surface units)", "cigi.symbol_circle_def.inner_radius5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_start_angle[4],
            { "Start Angle 5 (degrees)", "cigi.symbol_circle_def.start_angle5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_end_angle[4],
            { "End Angle 5 (degrees)", "cigi.symbol_circle_def.end_angle5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_u[5],
            { "Center U 6 (scaled symbol surface units)", "cigi.symbol_circle_def.center_u6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_v[5],
            { "Center V 6 (scaled symbol surface units)", "cigi.symbol_circle_def.center_v6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_radius[5],
            { "Radius 6 (scaled symbol surface units)", "cigi.symbol_circle_def.radius6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_inner_radius[5],
            { "Inner Radius 6 (scaled symbol surface units)", "cigi.symbol_circle_def.inner_radius6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_start_angle[5],
            { "Start Angle 6 (degrees)", "cigi.symbol_circle_def.start_angle6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_end_angle[5],
            { "End Angle 6 (degrees)", "cigi.symbol_circle_def.end_angle6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_u[6],
            { "Center U 7 (scaled symbol surface units)", "cigi.symbol_circle_def.center_u7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_v[6],
            { "Center V 7 (scaled symbol surface units)", "cigi.symbol_circle_def.center_v7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_radius[6],
            { "Radius 7 (scaled symbol surface units)", "cigi.symbol_circle_def.radius7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_inner_radius[6],
            { "Inner Radius 7 (scaled symbol surface units)", "cigi.symbol_circle_def.inner_radius7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_start_angle[6],
            { "Start Angle 7 (degrees)", "cigi.symbol_circle_def.start_angle7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_end_angle[6],
            { "End Angle 7 (degrees)", "cigi.symbol_circle_def.end_angle7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_u[7],
            { "Center U 8 (scaled symbol surface units)", "cigi.symbol_circle_def.center_u8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_v[7],
            { "Center V 8 (scaled symbol surface units)", "cigi.symbol_circle_def.center_v8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_radius[7],
            { "Radius 8 (scaled symbol surface units)", "cigi.symbol_circle_def.radius8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_inner_radius[7],
            { "Inner Radius 8 (scaled symbol surface units)", "cigi.symbol_circle_def.inner_radius8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_start_angle[7],
            { "Start Angle 8 (degrees)", "cigi.symbol_circle_def.start_angle8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_end_angle[7],
            { "End Angle 8 (degrees)", "cigi.symbol_circle_def.end_angle8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_u[8],
            { "Center U 9 (scaled symbol surface units)", "cigi.symbol_circle_def.center_u9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_center_v[8],
            { "Center V 9 (scaled symbol surface units)", "cigi.symbol_circle_def.center_v9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_radius[8],
            { "Radius 9 (scaled symbol surface units)", "cigi.symbol_circle_def.radius9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_inner_radius[8],
            { "Inner Radius 9 (scaled symbol surface units)", "cigi.symbol_circle_def.inner_radius9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_start_angle[8],
            { "Start Angle 9 (degrees)", "cigi.symbol_circle_def.start_angle9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi3_3_symbol_circle_definition_end_angle[8],
            { "End Angle 9 (degrees)", "cigi.symbol_circle_def.end_angle9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },

        /* CIGI4 Symbol Circle Definition */

        /* CIGI3_3 Symbol Line Definition */
        { &hf_cigi3_3_symbol_line_definition,
            { "Symbol Line Definition", "cigi.symbol_line_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Symbol Line Definition Packet", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_symbol_id,
            { "Symbol ID", "cigi.symbol_line_def.symbol_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the identifier of the symbol that is being defined", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_primitive_type,
            { "Primitive Type", "cigi.symbl_line_def.primitive_type",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_symbol_line_definition_primitive_type_vals), 0x0F,
                "Specifies the type of point or line primitive used", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_stipple_pattern,
            { "Stipple Pattern", "cigi.symbol_line_def.stipple_pattern",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "Specifies the dash pattern used", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_line_width,
            { "Line Width (scaled symbol surface units)", "cigi.symbol_line_def.line_width",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the thickness of the line", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_stipple_pattern_length,
            { "Stipple Pattern Length (scaled symbol surface units)", "cigi.symbol_line_def.stipple_pattern_length",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the length of one complete repetition of the stipple pattern", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[0],
            { "Vertex U 1 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[0],
            { "Vertex V 1 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[1],
            { "Vertex U 2 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[1],
            { "Vertex V 2 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[2],
            { "Vertex U 3 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[2],
            { "Vertex V 3 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[3],
            { "Vertex U 4 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[3],
            { "Vertex V 4 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[4],
            { "Vertex U 5 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[4],
            { "Vertex V 5 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[5],
            { "Vertex U 6 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[5],
            { "Vertex V 6 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[6],
            { "Vertex U 7 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[6],
            { "Vertex V 7 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[7],
            { "Vertex U 8 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[7],
            { "Vertex V 8 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[8],
            { "Vertex U 9 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[8],
            { "Vertex V 9 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[9],
            { "Vertex U 10 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u10",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[9],
            { "Vertex V 10 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v10",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[10],
            { "Vertex U 11 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u11",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[10],
            { "Vertex V 11 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v11",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[11],
            { "Vertex U 12 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u12",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[11],
            { "Vertex V 12 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v12",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[12],
            { "Vertex U 13 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u13",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[12],
            { "Vertex V 13 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v13",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[13],
            { "Vertex U 14 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u14",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[13],
            { "Vertex V 14 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v14",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[14],
            { "Vertex U 15 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u15",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[14],
            { "Vertex V 15 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v15",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[15],
            { "Vertex U 16 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u16",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[15],
            { "Vertex V 16 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v16",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[16],
            { "Vertex U 17 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u17",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[16],
            { "Vertex V 17 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v17",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[17],
            { "Vertex U 18 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u18",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[17],
            { "Vertex V 18 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v18",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[18],
            { "Vertex U 19 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u19",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[18],
            { "Vertex V 19 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v19",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[19],
            { "Vertex U 20 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u20",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[19],
            { "Vertex V 20 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v20",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[20],
            { "Vertex U 21 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u21",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[20],
            { "Vertex V 21 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v21",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[21],
            { "Vertex U 22 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u22",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[21],
            { "Vertex V 22 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v22",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[22],
            { "Vertex U 23 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u23",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[22],
            { "Vertex V 23 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v23",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[23],
            { "Vertex U 24 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u24",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[23],
            { "Vertex V 24 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v24",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[24],
            { "Vertex U 25 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u25",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[24],
            { "Vertex V 25 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v25",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[25],
            { "Vertex U 26 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u26",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[25],
            { "Vertex V 26 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v26",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[26],
            { "Vertex U 27 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u27",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[26],
            { "Vertex V 27 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v27",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[27],
            { "Vertex U 28 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u28",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[27],
            { "Vertex V 28 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v28",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_u[28],
            { "Vertex U 29 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_u29",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi3_3_symbol_line_definition_vertex_v[28],
            { "Vertex V 29 (scaled symbol surface units)", "cigi.symbol_line_def.vertex_v29",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },


        /* CIGI4 Symbol Polygon Definition */
        { &hf_cigi4_symbol_polygon_definition,
            { "Symbol Line Definition", "cigi.symbol_polygon_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Symbol Line Definition Packet", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_symbol_id,
            { "Symbol ID", "cigi.symbol_polygon_def.symbol_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the identifier of the symbol that is being defined", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_primitive_type,
            { "Primitive Type", "cigi.symbol_polygon_def.primitive_type",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_symbol_line_definition_primitive_type_vals), 0x0F,
                "Specifies the type of point or line primitive used", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_stipple_pattern,
            { "Stipple Pattern", "cigi.symbol_polygon_def.stipple_pattern",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "Specifies the dash pattern used", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_line_width,
            { "Line Width (scaled symbol surface units)", "cigi.symbol_polygon_def.line_width",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the thickness of the line", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_stipple_pattern_length,
            { "Stipple Pattern Length (scaled symbol surface units)", "cigi.symbol_polygon_def.stipple_pattern_length",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the length of one complete repetition of the stipple pattern", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertices,
            { "Vertices", "cigi.symbol_polygon_def.vertices",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[0],
            { "Vertex U 1 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[0],
            { "Vertex V 1 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[1],
            { "Vertex U 2 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[1],
            { "Vertex V 2 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[2],
            { "Vertex U 3 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[2],
            { "Vertex V 3 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[3],
            { "Vertex U 4 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[3],
            { "Vertex V 4 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[4],
            { "Vertex U 5 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[4],
            { "Vertex V 5 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[5],
            { "Vertex U 6 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[5],
            { "Vertex V 6 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[6],
            { "Vertex U 7 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[6],
            { "Vertex V 7 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[7],
            { "Vertex U 8 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[7],
            { "Vertex V 8 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[8],
            { "Vertex U 9 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[8],
            { "Vertex V 9 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[9],
            { "Vertex U 10 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u10",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[9],
            { "Vertex V 10 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v10",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[10],
            { "Vertex U 11 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u11",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[10],
            { "Vertex V 11 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v11",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[11],
            { "Vertex U 12 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u12",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[11],
            { "Vertex V 12 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v12",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[12],
            { "Vertex U 13 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u13",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[12],
            { "Vertex V 13 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v13",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[13],
            { "Vertex U 14 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u14",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[13],
            { "Vertex V 14 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v14",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[14],
            { "Vertex U 15 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u15",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[14],
            { "Vertex V 15 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v15",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[15],
            { "Vertex U 16 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u16",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[15],
            { "Vertex V 16 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v16",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[16],
            { "Vertex U 17 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u17",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[16],
            { "Vertex V 17 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v17",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[17],
            { "Vertex U 18 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u18",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[17],
            { "Vertex V 18 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v18",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[18],
            { "Vertex U 19 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u19",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[18],
            { "Vertex V 19 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v19",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[19],
            { "Vertex U 20 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u20",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[19],
            { "Vertex V 20 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v20",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[20],
            { "Vertex U 21 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u21",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[20],
            { "Vertex V 21 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v21",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[21],
            { "Vertex U 22 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u22",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[21],
            { "Vertex V 22 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v22",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[22],
            { "Vertex U 23 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u23",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[22],
            { "Vertex V 23 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v23",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[23],
            { "Vertex U 24 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u24",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[23],
            { "Vertex V 24 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v24",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[24],
            { "Vertex U 25 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u25",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[24],
            { "Vertex V 25 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v25",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[25],
            { "Vertex U 26 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u26",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[25],
            { "Vertex V 26 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v26",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[26],
            { "Vertex U 27 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u27",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[26],
            { "Vertex V 27 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v27",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[27],
            { "Vertex U 28 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u28",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[27],
            { "Vertex V 28 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v28",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_u[28],
            { "Vertex U 29 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_u29",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_definition_vertex_v[28],
            { "Vertex V 29 (scaled symbol surface units)", "cigi.symbol_polygon_def.vertex_v29",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },

        /* CIGI3_3 Symbol Clone */
        { &hf_cigi3_3_symbol_clone,
            { "Symbol Clone", "cigi.symbol_clone",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Symbol Clone Packet", HFILL }
        },
        { &hf_cigi3_3_symbol_clone_symbol_id,
            { "Symbol ID", "cigi.symbol_clone.symbol_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the identifier of the symbol that is being defined", HFILL }
        },
        { &hf_cigi3_3_symbol_clone_source_type,
            { "Source Type", "cigi.symbol_clone.source_type",
                FT_BOOLEAN, 8, TFS(&cigi3_3_symbol_clone_source_type_tfs), 0x04,
                "Identifies the source as an existing symbol or symbol template", HFILL }
        },
        { &hf_cigi3_3_symbol_clone_source_id,
            { "Source ID", "cigi.symbol_clone.source_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the symbol to copy or template to instantiate", HFILL }
        },


        /* CIGI4 Symbol Clone */

        /* CIGI3_3 Symbol Control */
        { &hf_cigi3_3_symbol_control,
            { "Symbol Control", "cigi.symbol_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Symbol Control Packet", HFILL }
        },
        { &hf_cigi3_3_symbol_control_symbol_id,
            { "Symbol ID", "cigi.symbol_control.symbol_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the symbol to which this packet is applied", HFILL }
        },
        { &hf_cigi3_3_symbol_control_symbol_state,
            { "Symbol State", "cigi.symbol_control.symbol_state",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_symbol_control_symbol_state_vals), 0x03,
                "Specifies whether the symbol should be hidden, visible, or destroyed", HFILL }
        },
        { &hf_cigi3_3_symbol_control_attach_state,
            { "Attach State", "cigi.symbol_control.attach_state",
                FT_BOOLEAN, 8, TFS(&attach_detach_tfs), 0x04,
                "Specifies whether this symbol should be attached to another", HFILL }
        },
        { &hf_cigi3_3_symbol_control_flash_control,
            { "Flash Control", "cigi.symbol_control.flash_control",
                FT_BOOLEAN, 8, TFS(&cigi3_3_symbol_control_flash_control_tfs), 0x08,
                "Specifies whether the flash cycle is continued or restarted", HFILL }
        },
        { &hf_cigi3_3_symbol_control_inherit_color,
            { "Inherit Color", "cigi.symbol_control.inherit_color",
                FT_BOOLEAN, 8, TFS(&inherited_not_inherited_tfs), 0x10,
                "Specifies whether the symbol inherits color from a parent symbol", HFILL }
        },
        { &hf_cigi3_3_symbol_control_parent_symbol_ident,
            { "Parent Symbol ID", "cigi.symbol_control.parent_symbol_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the parent for the symbol", HFILL }
        },
        { &hf_cigi3_3_symbol_control_surface_ident,
            { "Surface ID", "cigi.symbol_control.surface_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the symbol surface for the symbol", HFILL }
        },
        { &hf_cigi3_3_symbol_control_layer,
            { "Layer", "cigi.symbol_control.layer",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the layer for the symbol", HFILL }
        },
        { &hf_cigi3_3_symbol_control_flash_duty_cycle,
            { "Flash Duty Cycle (%)", "cigi.symbol_control.flash_duty_cycle",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the duty cycle for a flashing symbol", HFILL }
        },
        { &hf_cigi3_3_symbol_control_flash_period,
            { "Flash Period (seconds)", "cigi.symbol_control.flash_period",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the duration of a single flash cycle", HFILL }
        },
        { &hf_cigi3_3_symbol_control_position_u,
            { "Position U (scaled symbol surface units)", "cigi.symbol_control.position_u",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position", HFILL }
        },
        { &hf_cigi3_3_symbol_control_position_v,
            { "Position V (scaled symbol surface units)", "cigi.symbol_control.position_v",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position", HFILL }
        },
        { &hf_cigi3_3_symbol_control_rotation,
            { "Rotation (degrees)", "cigi.symbol_control.rotation",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation", HFILL }
        },
        { &hf_cigi3_3_symbol_control_red,
            { "Red", "cigi.symbol_control.red",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the red color component", HFILL }
        },
        { &hf_cigi3_3_symbol_control_green,
            { "Green", "cigi.symbol_control.green",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the green color component", HFILL }
        },
        { &hf_cigi3_3_symbol_control_blue,
            { "Blue", "cigi.symbol_control.blue",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the blue color component", HFILL }
        },
        { &hf_cigi3_3_symbol_control_alpha,
            { "Alpha", "cigi.symbol_control.alpha",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the alpha color component", HFILL }
        },
        { &hf_cigi3_3_symbol_control_scale_u,
            { "Scale U", "cigi.symbol_control.scale_u",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u scaling factor", HFILL }
        },
        { &hf_cigi3_3_symbol_control_scale_v,
            { "Scale V", "cigi.symbol_control.scale_v",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v scaling factor", HFILL }
        },

        /* CIGI4 Symbol Control */

        /* CIGI3_3 Short Symbol Control */
        { &hf_cigi3_3_short_symbol_control,
            { "Short Symbol Control", "cigi.short_symbol_control",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Short Symbol Control Packet", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_symbol_id,
            { "Symbol ID", "cigi.short_symbol_control.symbol_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the symbol to which this packet is applied", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_symbol_state,
            { "Symbol State", "cigi.short_symbol_control.symbol_state",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_symbol_control_symbol_state_vals), 0x03,
                "Specifies whether the symbol should be hidden, visible, or destroyed", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_attach_state,
            { "Attach State", "cigi.short_symbol_control.attach_state",
                FT_BOOLEAN, 8, TFS(&attach_detach_tfs), 0x04,
                "Specifies whether this symbol should be attached to another", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_flash_control,
            { "Flash Control", "cigi.short_symbol_control.flash_control",
                FT_BOOLEAN, 8, TFS(&cigi3_3_symbol_control_flash_control_tfs), 0x08,
                "Specifies whether the flash cycle is continued or restarted", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_inherit_color,
            { "Inherit Color", "cigi.short_symbol_control.inherit_color",
                FT_BOOLEAN, 8, TFS(&inherited_not_inherited_tfs), 0x10,
                "Specifies whether the symbol inherits color from a parent symbol", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_attribute_select1,
            { "Attribute Select 1", "cigi.short_symbol_control.attribute_select1",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_short_symbol_control_attribute_select_vals), 0x0,
                "Identifies the attribute whose value is specified in Attribute Value 1", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_attribute_select2,
            { "Attribute Select 2", "cigi.short_symbol_control.attribute_select2",
                FT_UINT8, BASE_DEC, VALS(cigi3_3_short_symbol_control_attribute_select_vals), 0x0,
                "Identifies the attribute whose value is specified in Attribute Value 2", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_attribute_value1,
            { "Value 1", "cigi.short_symbol_control.value1_uint",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Specifies the value for attribute 1", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_attribute_value2,
            { "Value 2", "cigi.short_symbol_control.value2_uint",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Specifies the value for attribute 2", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_attribute_value1f,
            { "Value 1", "cigi.short_symbol_control.value1_float",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the value for attribute 1", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_attribute_value2f,
            { "Value 2", "cigi.short_symbol_control.value2_float",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the value for attribute 2", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_red1,
            { "Red 1", "cigi.short_symbol_control.red1",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the red color component", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_green1,
            { "Green 1", "cigi.short_symbol_control.green1",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the green color component", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_blue1,
            { "Blue 1", "cigi.short_symbol_control.blue1",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the blue color component", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_alpha1,
            { "Alpha 1", "cigi.short_symbol_control.alpha1",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the alpha color component", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_red2,
            { "Red 2", "cigi.short_symbol_control.red2",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the red color component", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_green2,
            { "Green 2", "cigi.short_symbol_control.green2",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the green color component", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_blue2,
            { "Blue 2", "cigi.short_symbol_control.blue2",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the blue color component", HFILL }
        },
        { &hf_cigi3_3_short_symbol_control_alpha2,
            { "Alpha 2", "cigi.short_symbol_control.alpha2",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the alpha color component", HFILL }
        },

        /* CIGI4 Short Symbol Control */

        /* CIGI4 Symbol Circle Textured Definition */
        { &hf_cigi4_symbol_circle_textured_definition,
            { "Symbol Circle Textured Definition", "cigi.symbol_circle_textured_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Symbol Circle Definition Packet", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_symbol_id,
            { "Symbol ID", "cigi.symbol_circle_textured_def.symbol_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the identifier of the symbol that is being defined", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_id,
            { "Texture ID", "cigi.symbol_circle_textured_def.texture_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the identifier of the texture that is being applied", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_filter_mode,
            { "Filter Mode", "cigi.symbol_circle_textured_def.filter_mode",
                FT_BOOLEAN, 8, NULL, 0x01,
                "Specifies the type of texture filtering/interpolation applied to the symbol", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_wrap,
            { "Line Width (scaled symbol surface units)", "cigi.symbol_circle_textured_def.wrap",
                FT_BOOLEAN, 8, NULL, 0x02,
                "Specifies whether texture coordinates are to be wrapped or clamped when applied to the symbol", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_circles,
            { "Circles", "cigi.symbol_circle_textured_def.circles",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_u[0],
            { "Center U 1 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_u1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_v[0],
            { "Center V 1 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_v1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_radius[0],
            { "Radius 1 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.radius1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_inner_radius[0],
            { "Inner Radius 1 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.inner_radius1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_start_angle[0],
            { "Start Angle 1 (degrees)", "cigi.symbol_circle_textured_def.start_angle1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_end_angle[0],
            { "End Angle 1 (degrees)", "cigi.symbol_circle_textured_def.end_angle1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_u[0],
            { "Texture Coordinate S at Center Point", "cigi.symbol_circle_textured_def.texture_center_u1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_v[0],
            { "Texture Coordinate T at Center Point", "cigi.symbol_circle_textured_def.texture_center_v1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_radius[0],
            { "Texture Mapping Radius", "cigi.symbol_circle_textured_def.texture_mapping_radius1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the extents of the texture that is stretched to cover the circle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_rotation[0],
            { "Texture Mapping Rotation", "cigi.symbol_circle_textured_def.texture_mapping_rotation1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation of the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_u[1],
            { "Center U 2 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_u2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_v[1],
            { "Center V 2 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_v2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_radius[1],
            { "Radius 2 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.radius2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_inner_radius[1],
            { "Inner Radius 2 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.inner_radius2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_start_angle[1],
            { "Start Angle 2 (degrees)", "cigi.symbol_circle_textured_def.start_angle2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_end_angle[1],
            { "End Angle 2 (degrees)", "cigi.symbol_circle_textured_def.end_angle2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_u[1],
            { "Texture Coordinate S at Center Point", "cigi.symbol_circle_textured_def.texture_center_u2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_v[1],
            { "Texture Coordinate T at Center Point", "cigi.symbol_circle_textured_def.texture_center_v2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_radius[1],
            { "Texture Mapping Radius", "cigi.symbol_circle_textured_def.texture_mapping_radius2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the extents of the texture that is stretched to cover the circle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_rotation[1],
            { "Texture Mapping Rotation", "cigi.symbol_circle_textured_def.texture_mapping_rotation2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation of the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_u[2],
            { "Center U 3 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_u3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_v[2],
            { "Center V 3 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_v3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_radius[2],
            { "Radius 3 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.radius3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_inner_radius[2],
            { "Inner Radius 3 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.inner_radius3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_start_angle[2],
            { "Start Angle 3 (degrees)", "cigi.symbol_circle_textured_def.start_angle3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_end_angle[2],
            { "End Angle 3 (degrees)", "cigi.symbol_circle_textured_def.end_angle3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_u[2],
            { "Texture Coordinate S at Center Point", "cigi.symbol_circle_textured_def.texture_center_u3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_v[2],
            { "Texture Coordinate T at Center Point", "cigi.symbol_circle_textured_def.texture_center_v3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_radius[2],
            { "Texture Mapping Radius", "cigi.symbol_circle_textured_def.texture_mapping_radius3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the extents of the texture that is stretched to cover the circle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_rotation[2],
            { "Texture Mapping Rotation", "cigi.symbol_circle_textured_def.texture_mapping_rotation3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation of the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_u[3],
            { "Center U 4 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_u4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_v[3],
            { "Center V 4 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_v4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_radius[3],
            { "Radius 4 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.radius4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_inner_radius[3],
            { "Inner Radius 4 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.inner_radius4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_start_angle[3],
            { "Start Angle 4 (degrees)", "cigi.symbol_circle_textured_def.start_angle4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_end_angle[3],
            { "End Angle 4 (degrees)", "cigi.symbol_circle_textured_def.end_angle4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_u[3],
            { "Texture Coordinate S at Center Point", "cigi.symbol_circle_textured_def.texture_center_u4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_v[3],
            { "Texture Coordinate T at Center Point", "cigi.symbol_circle_textured_def.texture_center_v4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_radius[3],
            { "Texture Mapping Radius", "cigi.symbol_circle_textured_def.texture_mapping_radius4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the extents of the texture that is stretched to cover the circle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_rotation[3],
            { "Texture Mapping Rotation", "cigi.symbol_circle_textured_def.texture_mapping_rotation4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation of the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_u[4],
            { "Center U 5 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_u5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_v[4],
            { "Center V 5 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_v5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_radius[4],
            { "Radius 5 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.radius5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_inner_radius[4],
            { "Inner Radius 5 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.inner_radius5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_start_angle[4],
            { "Start Angle 5 (degrees)", "cigi.symbol_circle_textured_def.start_angle5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_end_angle[4],
            { "End Angle 5 (degrees)", "cigi.symbol_circle_textured_def.end_angle5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_u[4],
            { "Texture Coordinate S at Center Point", "cigi.symbol_circle_textured_def.texture_center_u5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_v[4],
            { "Texture Coordinate T at Center Point", "cigi.symbol_circle_textured_def.texture_center_v5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_radius[4],
            { "Texture Mapping Radius", "cigi.symbol_circle_textured_def.texture_mapping_radius5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the extents of the texture that is stretched to cover the circle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_rotation[4],
            { "Texture Mapping Rotation", "cigi.symbol_circle_textured_def.texture_mapping_rotation5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation of the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_u[5],
            { "Center U 6 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_u6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_v[5],
            { "Center V 6 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_v6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_radius[5],
            { "Radius 6 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.radius6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_inner_radius[5],
            { "Inner Radius 6 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.inner_radius6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_start_angle[5],
            { "Start Angle 6 (degrees)", "cigi.symbol_circle_textured_def.start_angle6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_end_angle[5],
            { "End Angle 6 (degrees)", "cigi.symbol_circle_textured_def.end_angle6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_u[5],
            { "Texture Coordinate S at Center Point", "cigi.symbol_circle_textured_def.texture_center_u6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_v[5],
            { "Texture Coordinate T at Center Point", "cigi.symbol_circle_textured_def.texture_center_v6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_radius[5],
            { "Texture Mapping Radius", "cigi.symbol_circle_textured_def.texture_mapping_radius6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the extents of the texture that is stretched to cover the circle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_rotation[5],
            { "Texture Mapping Rotation", "cigi.symbol_circle_textured_def.texture_mapping_rotation6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation of the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_u[6],
            { "Center U 7 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_u7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_v[6],
            { "Center V 7 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_v7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_radius[6],
            { "Radius 7 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.radius7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_inner_radius[6],
            { "Inner Radius 7 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.inner_radius7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_start_angle[6],
            { "Start Angle 7 (degrees)", "cigi.symbol_circle_textured_def.start_angle7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_end_angle[6],
            { "End Angle 7 (degrees)", "cigi.symbol_circle_textured_def.end_angle7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_u[6],
            { "Texture Coordinate S at Center Point", "cigi.symbol_circle_textured_def.texture_center_u7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_v[6],
            { "Texture Coordinate T at Center Point", "cigi.symbol_circle_textured_def.texture_center_v7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_radius[6],
            { "Texture Mapping Radius", "cigi.symbol_circle_textured_def.texture_mapping_radius7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the extents of the texture that is stretched to cover the circle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_rotation[6],
            { "Texture Mapping Rotation", "cigi.symbol_circle_textured_def.texture_mapping_rotation7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation of the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_u[7],
            { "Center U 8 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_u8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_v[7],
            { "Center V 8 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_v8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_radius[7],
            { "Radius 8 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.radius8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_inner_radius[7],
            { "Inner Radius 8 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.inner_radius8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_start_angle[7],
            { "Start Angle 8 (degrees)", "cigi.symbol_circle_textured_def.start_angle8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_end_angle[7],
            { "End Angle 8 (degrees)", "cigi.symbol_circle_textured_def.end_angle8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_u[7],
            { "Texture Coordinate S at Center Point", "cigi.symbol_circle_textured_def.texture_center_u8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_v[7],
            { "Texture Coordinate T at Center Point", "cigi.symbol_circle_textured_def.texture_center_v8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_radius[7],
            { "Texture Mapping Radius", "cigi.symbol_circle_textured_def.texture_mapping_radius8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the extents of the texture that is stretched to cover the circle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_rotation[7],
            { "Texture Mapping Rotation", "cigi.symbol_circle_textured_def.texture_mapping_rotation8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation of the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_u[8],
            { "Center U 9 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_u9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_center_v[8],
            { "Center V 9 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.center_v9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_radius[8],
            { "Radius 9 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.radius9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_inner_radius[8],
            { "Inner Radius 9 (scaled symbol surface units)", "cigi.symbol_circle_textured_def.inner_radius9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the inner radius", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_start_angle[8],
            { "Start Angle 9 (degrees)", "cigi.symbol_circle_textured_def.start_angle9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the start angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_end_angle[8],
            { "End Angle 9 (degrees)", "cigi.symbol_circle_textured_def.end_angle9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the end angle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_u[8],
            { "Texture Coordinate S at Center Point", "cigi.symbol_circle_textured_def.texture_center_u9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_center_v[8],
            { "Texture Coordinate T at Center Point", "cigi.symbol_circle_textured_def.texture_center_v9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the circle’s center", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_radius[8],
            { "Texture Mapping Radius", "cigi.symbol_circle_textured_def.texture_mapping_radius9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the extents of the texture that is stretched to cover the circle", HFILL }
        },
        { &hf_cigi4_symbol_circle_textured_definition_texture_rotation[8],
            { "Texture Mapping Rotation", "cigi.symbol_circle_textured_def.texture_mapping_rotation9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the rotation of the texture relative to the circle’s center", HFILL }
        },

        /* CIGI4 Symbol Polygon Textured Definition */
        { &hf_cigi4_symbol_polygon_textured_definition,
            { "Symbol Textured Polygon Definition", "cigi.symbol_polygon_textured_def",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Symbol Circle Definition Packet", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_symbol_id,
            { "Symbol ID", "cigi.symbol_polygon_textured_def.symbol_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the identifier of the symbol that is being defined", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_id,
            { "Texture ID", "cigi.symbol_polygon_textured_def.texture_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the identifier of the texture that is being applied", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_filter_mode,
            { "Filter Mode", "cigi.symbol_polygon_textured_def.filter_mode",
                FT_BOOLEAN, 8, NULL, 0x01,
                "Specifies the type of texture filtering/interpolation applied to the symbol", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_wrap,
            { "Line Width (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.wrap",
                FT_BOOLEAN, 8, NULL, 0x02,
                "Specifies whether texture coordinates are to be wrapped or clamped when applied to the symbol", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertices,
            { "Vertices", "cigi.symbol_polygon_textured_def.vertices",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[0],
            { "Vertex U 1 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[0],
            { "Vertex V 1 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[0],
            { "Center U 1 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[0],
            { "Center V 1 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v1",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[1],
            { "Vertex U 2 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[1],
            { "Vertex V 2 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[1],
            { "Center U 2 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[1],
            { "Center V 2 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v2",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[2],
            { "Vertex U 3 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[2],
            { "Vertex V 3 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[2],
            { "Center U 3 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[2],
            { "Center V 3 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v3",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[3],
            { "Vertex U 4 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[3],
            { "Vertex V 4 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[3],
            { "Center U 4 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[3],
            { "Center V 4 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v4",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[4],
            { "Vertex U 5 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[4],
            { "Vertex V 5 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[4],
            { "Center U 5 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[4],
            { "Center V 5 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v5",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[5],
            { "Vertex U 6 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[5],
            { "Vertex V 6 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[5],
            { "Center U 6 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[5],
            { "Center V 6 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v6",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[6],
            { "Vertex U 7 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[6],
            { "Vertex V 7 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[6],
            { "Center U 7 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[6],
            { "Center V 7 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v7",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[7],
            { "Vertex U 8 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[7],
            { "Vertex V 8 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[7],
            { "Center U 8 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[7],
            { "Center V 8 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v8",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[8],
            { "Vertex U 9 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[8],
            { "Vertex V 9 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[8],
            { "Center U 9 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[8],
            { "Center V 9 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v9",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[9],
            { "Vertex U 10 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u10",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[9],
            { "Vertex V 10 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v10",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[9],
            { "Center U 10 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u10",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[9],
            { "Center V 10 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v10",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[10],
            { "Vertex U 11 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u11",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[10],
            { "Vertex V 11 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v11",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[10],
            { "Center U 11 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u11",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[10],
            { "Center V 11 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v11",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[11],
            { "Vertex U 12 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u12",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[11],
            { "Vertex V 12 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v12",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[11],
            { "Center U 12 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u12",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[11],
            { "Center V 12 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v12",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[12],
            { "Vertex U 13 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u13",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[12],
            { "Vertex V 13 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v13",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[12],
            { "Center U 13 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u13",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[12],
            { "Center V 13 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v13",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[13],
            { "Vertex U 14 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u14",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[13],
            { "Vertex V 14 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v14",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[13],
            { "Center U 14 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u14",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[13],
            { "Center V 14 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v14",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[14],
            { "Vertex U 15 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u15",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[14],
            { "Vertex V 15 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v15",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[14],
            { "Center U 15 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u15",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[14],
            { "Center V 15 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v15",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[15],
            { "Vertex U 16 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u16",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[15],
            { "Vertex V 16 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v16",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[15],
            { "Center U 16 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u16",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[15],
            { "Center V 16 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v16",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[16],
            { "Vertex U 17 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u17",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[16],
            { "Vertex V 17 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v17",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[16],
            { "Center U 17 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u17",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[16],
            { "Center V 17 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v17",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[17],
            { "Vertex U 18 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u18",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[17],
            { "Vertex V 18 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v18",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[17],
            { "Center U 18 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u18",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[17],
            { "Center V 18 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v18",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[18],
            { "Vertex U 19 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u19",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[18],
            { "Vertex V 19 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v19",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[18],
            { "Center U 19 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u19",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[18],
            { "Center V 19 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v19",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[19],
            { "Vertex U 20 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u20",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[19],
            { "Vertex V 20 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v20",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[19],
            { "Center U 1 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u20",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[19],
            { "Center V 1 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v20",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[20],
            { "Vertex U 21 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u21",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[20],
            { "Vertex V 21 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v21",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[20],
            { "Center U 21 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u21",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[20],
            { "Center V 21 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v21",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[21],
            { "Vertex U 22 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u22",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[21],
            { "Vertex V 22 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v22",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[21],
            { "Center U 22 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u22",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[21],
            { "Center V 22 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v22",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[22],
            { "Vertex U 23 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u23",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[22],
            { "Vertex V 23 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v23",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[22],
            { "Center U 23 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u23",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[22],
            { "Center V 23 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v23",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[23],
            { "Vertex U 24 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u24",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[23],
            { "Vertex V 24 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v24",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[23],
            { "Center U 24 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u24",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[23],
            { "Center V 24 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v24",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[24],
            { "Vertex U 25 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u25",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[24],
            { "Vertex V 25 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v25",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[24],
            { "Center U 25 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u25",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[24],
            { "Center V 25 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v25",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[25],
            { "Vertex U 26 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u26",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[25],
            { "Vertex V 26 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v26",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[25],
            { "Center U 26 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u26",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[25],
            { "Center V 26 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v26",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[26],
            { "Vertex U 27 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u27",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[26],
            { "Vertex V 27 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v27",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[26],
            { "Center U 27 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u27",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[26],
            { "Center V 27 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v27",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[27],
            { "Vertex U 28 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u28",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[27],
            { "Vertex V 28 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v28",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[27],
            { "Center U 28 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u28",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[27],
            { "Center V 28 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v28",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_u[28],
            { "Vertex U 29 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_u29",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the u position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_vertex_v[28],
            { "Vertex V 29 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.vertex_v29",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the v position of the vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_u[28],
            { "Center U 29 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_u29",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized S texture coordinate to position the texture relative to the associated vertex", HFILL }
        },
        { &hf_cigi4_symbol_polygon_textured_definition_texture_center_v[28],
            { "Center V 29 (scaled symbol surface units)", "cigi.symbol_polygon_textured_def.center_v29",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the normalized T texture coordinate to position the texture relative to the associated vertex", HFILL }
        },

        /* CIGI2 Start of Frame */
        { &hf_cigi2_start_of_frame,
            { "Start of Frame", "cigi.sof",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Start of Frame Packet", HFILL }
        },
        { &hf_cigi2_start_of_frame_db_number,
            { "Database Number", "cigi.sof.db_number",
                FT_INT8, BASE_DEC, NULL, 0x0,
                "Indicates load status of the requested database", HFILL }
        },
        { &hf_cigi2_start_of_frame_ig_status_code,
            { "IG Status Code", "cigi.sof.ig_status_code",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the operational status of the IG", HFILL }
        },
        { &hf_cigi2_start_of_frame_ig_mode,
            { "IG Mode", "cigi.sof.ig_mode",
                FT_UINT8, BASE_DEC, VALS(cigi2_start_of_frame_ig_mode_vals), 0xc0,
                "Identifies to the host the current operating mode of the IG", HFILL }
        },
        { &hf_cigi2_start_of_frame_frame_ctr,
            { "IG to Host Frame Counter", "cigi.sof.frame_ctr",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Contains a number representing a particular frame", HFILL }
        },
        { &hf_cigi2_start_of_frame_time_tag,
            { "Timing Value (microseconds)", "cigi.sof.time_tag",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Contains a timing value that is used to time-tag the ethernet message during asynchronous operation", HFILL }
        },

        /* CIGI3 Start of Frame */
        { &hf_cigi3_start_of_frame,
            { "Start of Frame", "cigi.sof",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Start of Frame Packet", HFILL }
        },
        { &hf_cigi3_start_of_frame_db_number,
            { "Database Number", "cigi.sof.db_number",
                FT_INT8, BASE_DEC, NULL, 0x0,
                "Indicates to the Host which database is currently in use and if that database is being loaded into primary memory", HFILL }
        },
        { &hf_cigi3_start_of_frame_ig_status,
            { "IG Status Code", "cigi.sof.ig_status",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the error status of the IG", HFILL }
        },
        { &hf_cigi3_start_of_frame_ig_mode,
            { "IG Mode", "cigi.sof.ig_mode",
                FT_UINT8, BASE_DEC, VALS(cigi3_start_of_frame_ig_mode_vals), 0x03,
                "Indicates the current IG mode", HFILL }
        },
        { &hf_cigi3_start_of_frame_timestamp_valid,
            { "Timestamp Valid", "cigi.sof.timestamp_valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x04,
                "Indicates whether the Timestamp parameter contains a valid value", HFILL }
        },
        { &hf_cigi3_start_of_frame_earth_reference_model,
            { "Earth Reference Model", "cigi.sof.earth_reference_model",
                FT_BOOLEAN, 8, TFS(&cigi3_start_of_frame_earth_reference_model_tfs), 0x08,
                "Indicates whether the IG is using a custom Earth Reference Model or the default WGS 84 reference ellipsoid for coordinate conversion calculations", HFILL }
        },
        { &hf_cigi3_start_of_frame_frame_ctr,
            { "Frame Counter", "cigi.sof.frame_ctr",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Contains a number that identifies the frame", HFILL }
        },
        { &hf_cigi3_start_of_frame_timestamp,
            { "Timestamp (microseconds)", "cigi.sof.timestamp",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Indicates the number of 10 microsecond \"ticks\" since some initial reference time", HFILL }
        },

        /* CIGI3_2 Start of Frame */
        { &hf_cigi3_2_start_of_frame,
            { "Start of Frame", "cigi.sof",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Start of Frame Packet", HFILL }
        },
        { &hf_cigi3_2_start_of_frame_minor_version,
            { "Minor Version", "cigi.sof.minor_version",
                FT_UINT8, BASE_DEC, NULL, 0xF0,
                "Indicates the minor version of the CIGI interface", HFILL }
        },
        { &hf_cigi3_2_start_of_frame_ig_frame_number,
            { "IG Frame Number", "cigi.sof.ig_frame_number",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Uniquely identifies the IG data frame", HFILL }
        },
        { &hf_cigi3_2_start_of_frame_last_host_frame_number,
            { "Last Host Frame Number", "cigi.sof.last_host_frame_number",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Contains the value of the Host Frame parameter in the last IG Control packet received from the Host.", HFILL }
        },

        /* CIGI4 Start of Frame */
        { &hf_cigi4_start_of_frame,
            { "Start of Frame", "cigi.sof",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Start of Frame Packet", HFILL }
        },
        { &hf_cigi4_start_of_frame_db_number,
            { "Database Number", "cigi.sof.db_number",
                FT_INT8, BASE_DEC, NULL, 0x0,
                "Indicates to the Host which database is currently in use and if that database is being loaded into primary memory", HFILL }
        },
        { &hf_cigi4_start_of_frame_ig_status,
            { "IG Status Code", "cigi.sof.ig_status",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the error status of the IG", HFILL }
        },
        { &hf_cigi4_start_of_frame_minor_version,
            { "Minor Version", "cigi.sof.minor_version",
                FT_UINT8, BASE_DEC, NULL, 0xF0,
                "Indicates the minor version of the CIGI interface", HFILL }
        },
        { &hf_cigi4_start_of_frame_flags,
            { "Flags", "cigi.sof.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi4_start_of_frame_ig_mode,
            { "IG Mode", "cigi.sof.ig_mode",
                FT_UINT8, BASE_DEC, VALS(cigi3_start_of_frame_ig_mode_vals), 0x03,
                "Indicates the current IG mode", HFILL }
        },
        { &hf_cigi4_start_of_frame_timestamp_valid,
            { "Timestamp Valid", "cigi.sof.timestamp_valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x04,
                "Indicates whether the Timestamp parameter contains a valid value", HFILL }
        },
        { &hf_cigi4_start_of_frame_earth_reference_model,
            { "Earth Reference Model", "cigi.sof.earth_reference_model",
                FT_BOOLEAN, 8, TFS(&cigi3_start_of_frame_earth_reference_model_tfs), 0x08,
                "Indicates whether the IG is using a custom Earth Reference Model or the default WGS 84 reference ellipsoid for coordinate conversion calculations", HFILL }
        },
        { &hf_cigi4_start_of_frame_ig_frame_number,
            { "IG Frame Number", "cigi.sof.ig_frame_number",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Uniquely identifies the IG data frame", HFILL }
        },
        { &hf_cigi4_start_of_frame_timestamp,
            { "Timestamp (microseconds)", "cigi.sof.timestamp",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Indicates the number of 10 microsecond \"ticks\" since some initial reference time", HFILL }
        },
        { &hf_cigi4_start_of_frame_last_host_frame_number,
            { "Last Host Frame Number", "cigi.sof.last_host_frame_number",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Contains the value of the Host Frame parameter in the last IG Control packet received from the Host.", HFILL }
        },
        { &hf_cigi4_start_of_frame_ig_condition_flags,
            { "IG Condition Flags", "cigi.sof.ig_condition_flags",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_cigi4_start_of_frame_condition_overframing,
            { "Overframing", "cigi.sof.overframing",
                FT_BOOLEAN, 8, NULL, 0x01,
                "The IG shall set this parameter to one (1) when the overframing condition is detected", HFILL }
        },
        { &hf_cigi4_start_of_frame_condition_paging,
            { "Paging", "cigi.sof.paging",
                FT_BOOLEAN, 8, NULL, 0x02,
                "The IG shall set this parameter to one (1) when the paging condition is present", HFILL }
        },
        { &hf_cigi4_start_of_frame_condition_excessive_variable_length_data,
            { "Excessive Variable Length Data", "cigi.sof.excessive_variable_length_data",
                FT_BOOLEAN, 8, NULL, 0x04,
                "The IG shall set this parameter to one (1) when the excessive variable length data condition is detected", HFILL }
        },

        /* CIGI2 Height Above Terrain Response */
        { &hf_cigi2_height_above_terrain_response,
            { "Height Above Terrain Response", "cigi.hat_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Height Above Terrain Response Packet", HFILL }
        },
        { &hf_cigi2_height_above_terrain_response_hat_id,
            { "HAT ID", "cigi.hat_response.hat_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the HAT response", HFILL }
        },
        { &hf_cigi2_height_above_terrain_response_valid,
            { "Valid", "cigi.hat_response.valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x80,
                "Indicates whether the response is valid or invalid", HFILL }
        },
        { &hf_cigi2_height_above_terrain_response_material_type,
            { "Material Type", "cigi.hat_response.material_type",
                FT_INT32, BASE_DEC, NULL, 0x0,
                "Specifies the material type of the object intersected by the HAT test vector", HFILL }
        },
        { &hf_cigi2_height_above_terrain_response_alt,
            { "Altitude (m)", "cigi.hat_response.alt",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Represents the altitude above or below the terrain for the position requested", HFILL }
        },

        /* CIGI3 HAT/HOT Response */
        { &hf_cigi3_hat_hot_response,
            { "HAT/HOT Response", "cigi.hat_hot_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "HAT/HOT Response Packet", HFILL }
        },
        { &hf_cigi3_hat_hot_response_hat_hot_id,
            { "HAT/HOT ID", "cigi.hat_hot_response.hat_hot_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the HAT or HOT response", HFILL }
        },
        { &hf_cigi3_hat_hot_response_valid,
            { "Valid", "cigi.hat_hot_response.valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x01,
                "Indicates whether the Height parameter contains a valid number", HFILL }
        },
        { &hf_cigi3_hat_hot_response_type,
            { "Response Type", "cigi.hat_hot_response.type",
                FT_BOOLEAN, 8, TFS(&cigi3_hat_hot_response_type_tfs), 0x02,
                "Indicates whether the Height parameter represent Height Above Terrain or Height Of Terrain", HFILL }
        },
        { &hf_cigi3_hat_hot_response_height,
            { "Height", "cigi.hat_hot_response.height",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Contains the requested height", HFILL }
        },

        /* CIGI3_2 HAT/HOT Response */
        { &hf_cigi3_2_hat_hot_response_host_frame_number_lsn,
            { "Host Frame Number LSN", "cigi.hat_hot_response.host_frame_number_lsn",
                FT_UINT8, BASE_DEC, NULL, 0xf0,
                "Least significant nibble of the host frame number parameter of the last IG Control packet received before the HAT or HOT is calculated", HFILL }
        },

        /* CIGI4 HAT/HOT Response */
        { &hf_cigi4_hat_hot_response_flags,
            { "Request Flags", "cigi.hat_hot_response.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },

        /* CIGI3 HAT/HOT Extended Response */
        { &hf_cigi3_hat_hot_extended_response,
            { "HAT/HOT Extended Response", "cigi.hat_hot_ext_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "HAT/HOT Extended Response Packet", HFILL }
        },
        { &hf_cigi3_hat_hot_extended_response_hat_hot_id,
            { "HAT/HOT ID", "cigi.hat_hot_ext_response.hat_hot_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the HAT/HOT response", HFILL }
        },
        { &hf_cigi3_hat_hot_extended_response_valid,
            { "Valid", "cigi.hat_hot_ext_response.valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x01,
                "Indicates whether the remaining parameters in this packet contain valid numbers", HFILL }
        },
        { &hf_cigi3_hat_hot_extended_response_hat,
            { "HAT", "cigi.hat_hot_ext_response.hat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the height of the test point above the terrain", HFILL }
        },
        { &hf_cigi3_hat_hot_extended_response_hot,
            { "HOT", "cigi.hat_hot_ext_response.hot",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the height of terrain above or below the test point", HFILL }
        },
        { &hf_cigi3_hat_hot_extended_response_material_code,
            { "Material Code", "cigi.hat_hot_ext_response.material_code",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Indicates the material code of the terrain surface at the point of intersection with the HAT/HOT test vector", HFILL }
        },
        { &hf_cigi3_hat_hot_extended_response_normal_vector_azimuth,
            { "Normal Vector Azimuth (degrees)", "cigi.hat_hot_ext_response.normal_vector_azimuth",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the azimuth of the normal unit vector of the surface intersected by the HAT/HOT test vector", HFILL }
        },
        { &hf_cigi3_hat_hot_extended_response_normal_vector_elevation,
            { "Normal Vector Elevation (degrees)", "cigi.hat_hot_ext_response.normal_vector_elevation",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the elevation of the normal unit vector of the surface intersected by the HAT/HOT test vector", HFILL }
        },

        /* CIGI3_2 HAT/HOT Extended Response */
        { &hf_cigi3_2_hat_hot_extended_response_host_frame_number_lsn,
            { "Host Frame Number LSN", "cigi.hat_hot_ext_response.host_frame_number_lsn",
                FT_UINT8, BASE_DEC, NULL, 0xf0,
                "Least significant nibble of the host frame number parameter of the last IG Control packet received before the HAT or HOT is calculated", HFILL }
        },

        /* CIGI4 HAT/HOT Extended Response */
        { &hf_cigi4_hat_hot_extended_response_flags,
            { "Request Flags", "cigi.hat_hot_extended_response.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },

        /* CIGI2 Line of Sight Response */
        { &hf_cigi2_line_of_sight_response,
            { "Line of Sight Response", "cigi.los_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Line of Sight Response Packet", HFILL }
        },
        { &hf_cigi2_line_of_sight_response_los_id,
            { "LOS ID", "cigi.los_response.los_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the LOS response corresponding tot he associated LOS request", HFILL }
        },
        { &hf_cigi2_line_of_sight_response_valid,
            { "Valid", "cigi.los_response.valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x80,
                "Indicates whether the response is valid or invalid", HFILL }
        },
        { &hf_cigi2_line_of_sight_response_occult_response,
            { "Occult Response", "cigi.los_response.occult_response",
                FT_BOOLEAN, 8, TFS(&visible_occulted_tfs), 0x40,
                "Used to respond to the LOS occult request data packet", HFILL }
        },
        { &hf_cigi2_line_of_sight_response_material_type,
            { "Material Type", "cigi.los_response.material_type",
                FT_INT32, BASE_DEC, NULL, 0x0,
                "Specifies the material type of the object intersected by the LOS test segment", HFILL }
        },
        { &hf_cigi2_line_of_sight_response_range,
            { "Range (m)", "cigi.los_response.range",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Used to respond to the Line of Sight Range Request data packet", HFILL }
        },
        { &hf_cigi2_line_of_sight_response_alt,
            { "Intersection Altitude (m)", "cigi.los_response.alt",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the altitude of the point of intersection of the LOS request vector with an object", HFILL }
        },
        { &hf_cigi2_line_of_sight_response_lat,
            { "Intersection Latitude (degrees)", "cigi.los_response.lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the latitudinal position of the intersection point of the LOS request vector with an object", HFILL }
        },
        { &hf_cigi2_line_of_sight_response_lon,
            { "Intersection Longitude (degrees)", "cigi.los_response.lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Specifies the longitudinal position of the intersection point of the LOS request vector with an object", HFILL }
        },

        /* CIGI3 Line of Sight Response */
        { &hf_cigi3_line_of_sight_response,
            { "Line of Sight Response", "cigi.los_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Line of Sight Response Packet", HFILL }
        },
        { &hf_cigi3_line_of_sight_response_los_id,
            { "LOS ID", "cigi.los_response.los_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the LOS response", HFILL }
        },
        { &hf_cigi3_line_of_sight_response_valid,
            { "Valid", "cigi.los_response.valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x01,
                "Indicates whether the Range parameter is valid", HFILL }
        },
        { &hf_cigi3_line_of_sight_response_entity_id_valid,
            { "Entity ID Valid", "cigi.los_response.entity_id_valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x02,
                "Indicates whether the LOS test vector or segment intersects with an entity or a non-entity", HFILL }
        },
        { &hf_cigi3_line_of_sight_response_visible,
            { "Visible", "cigi.los_response.visible",
                FT_BOOLEAN, 8, TFS(&visible_occluded_tfs), 0x04,
                "Indicates whether the destination point is visible from the source point", HFILL }
        },
        { &hf_cigi3_line_of_sight_response_count,
            { "Response Count", "cigi.los_response.count",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the total number of Line of Sight Response packets the IG will return for the corresponding request", HFILL }
        },
        { &hf_cigi3_line_of_sight_response_entity_id,
            { "Entity ID", "cigi.los_response.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity with which an LOS test vector or segment intersects", HFILL }
        },
        { &hf_cigi3_line_of_sight_response_range,
            { "Range (m)", "cigi.los_response.range",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the distance along the LOS test segment or vector from the source point to the point of intersection with a polygon surface", HFILL }
        },

        /* CIGI3_2 Line of Sight Response */
        { &hf_cigi3_2_line_of_sight_response_host_frame_number_lsn,
            { "Host Frame Number LSN", "cigi.los_response.host_frame_number_lsn",
                FT_UINT8, BASE_DEC, NULL, 0xf0,
                "Least significant nibble of the host frame number parameter of the last IG Control packet received before the HAT or HOT is calculated", HFILL }
        },

        /* CIGI4 Line of Sight Response */

        /* CIGI3 Line of Sight Extended Response */
        { &hf_cigi3_line_of_sight_extended_response,
            { "Line of Sight Extended Response", "cigi.los_ext_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Line of Sight Extended Response Packet", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_los_id,
            { "LOS ID", "cigi.los_ext_response.los_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the LOS response", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_valid,
            { "Valid", "cigi.los_ext_response.valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x01,
                "Indicates whether this packet contains valid data", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_entity_id_valid,
            { "Entity ID Valid", "cigi.los_ext_response.entity_id_valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x02,
                "Indicates whether the LOS test vector or segment intersects with an entity", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_range_valid,
            { "Range Valid", "cigi.los_ext_response.range_valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x04,
                "Indicates whether the Range parameter is valid", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_visible,
            { "Visible", "cigi.los_ext_response.visible",
                FT_BOOLEAN, 8, TFS(&visible_occluded_tfs), 0x08,
                "Indicates whether the destination point is visible from the source point", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_intersection_coord,
            { "Intersection Point Coordinate System", "cigi.los_ext_response.intersection_coord",
                FT_BOOLEAN, 8, TFS(&entity_geodetic_tfs), 0x10,
                "Indicates the coordinate system relative to which the intersection point is specified", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_response_count,
            { "Response Count", "cigi.los_ext_response.response_count",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the total number of Line of Sight Extended Response packets the IG will return for the corresponding request", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_entity_id,
            { "Entity ID", "cigi.los_ext_response.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity with which a LOS test vector or segment intersects", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_range,
            { "Range (m)", "cigi.los_ext_response.range",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the distance along the LOS test segment or vector from the source point to the point of intersection with an object", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_lat_xoff,
            { "Latitude (degrees)/X Offset (m)", "cigi.los_ext_response.lat_xoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the geodetic latitude of the point of intersection along the LOS test segment or vector or specifies the offset of the point of intersection of the LOS test segment or vector along the intersected entity's X axis", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_lon_yoff,
            { "Longitude (degrees)/Y Offset (m)", "cigi.los_ext_response.lon_yoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the geodetic longitude of the point of intersection along the LOS test segment or vector or specifies the offset of the point of intersection of the LOS test segment or vector along the intersected entity's Y axis", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_alt_zoff,
            { "Altitude (m)/Z Offset(m)", "cigi.los_ext_response.alt_zoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the geodetic altitude of the point of intersection along the LOS test segment or vector or specifies the offset of the point of intersection of the LOS test segment or vector along the intersected entity's Z axis", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_red,
            { "Red", "cigi.los_ext_response.red",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the red color component of the surface at the point of intersection", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_green,
            { "Green", "cigi.los_ext_response.green",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the green color component of the surface at the point of intersection", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_blue,
            { "Blue", "cigi.los_ext_response.blue",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the blue color component of the surface at the point of intersection", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_alpha,
            { "Alpha", "cigi.los_ext_response.alpha",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the alpha component of the surface at the point of intersection", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_material_code,
            { "Material Code", "cigi.los_ext_response.material_code",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Indicates the material code of the surface intersected by the LOS test segment of vector", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_normal_vector_azimuth,
            { "Normal Vector Azimuth (degrees)", "cigi.los_ext_response.normal_vector_azimuth",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the azimuth of a unit vector normal to the surface intersected by the LOS test segment or vector", HFILL }
        },
        { &hf_cigi3_line_of_sight_extended_response_normal_vector_elevation,
            { "Normal Vector Elevation (degrees)", "cigi.los_ext_response.normal_vector_elevation",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the elevation of a unit vector normal to the surface intersected by the LOS test segment or vector", HFILL }
        },

        /* CIGI3_2 Line of Sight Extended Response */
        { &hf_cigi3_2_line_of_sight_extended_response_host_frame_number_lsn,
            { "Host Frame Number LSN", "cigi.los_ext_response.host_frame_number_lsn",
                FT_UINT8, BASE_DEC, NULL, 0xf0,
                "Least significant nibble of the host frame number parameter of the last IG Control packet received before the HAT or HOT is calculated", HFILL }
        },

        /* CIGI4 Line of Sight Extended Response */

        /* CIGI2 Collision Detection Segment Response */
        { &hf_cigi2_collision_detection_segment_response,
            { "Collision Detection Segment Response", "cigi.coll_det_seg_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Collision Detection Segment Response Packet", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_response_entity_id,
            { "Entity ID", "cigi.coll_det_seg_response.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates which entity experienced a collision", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_response_segment_id,
            { "Segment ID", "cigi.coll_det_seg_response.segment_id",
                FT_UINT8, BASE_DEC, NULL, 0xfe,
                "Identifies the collision segment", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_response_contact,
            { "Entity/Non-Entity Contact", "cigi.coll_det_seg_response.contact",
                FT_BOOLEAN, 8, TFS(&cigi2_collision_detection_segment_response_contact_tfs), 0x01,
                "Indicates whether another entity was contacted during this collision", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_response_contacted_entity,
            { "Contacted Entity ID", "cigi.coll_det_seg_response.contacted_entity",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates which entity was contacted during the collision", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_response_material_type,
            { "Material Type", "cigi.coll_det_seg_response.material_type",
                FT_INT32, BASE_DEC, NULL, 0x0,
                "Specifies the material type of the surface that this collision test segment contacted", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_response_collision_x,
            { "Collision Point X (m)", "cigi.coll_det_seg_response.collision_x",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the X component of a vector, which lies along the defined segment where the segment intersected a surface", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_response_collision_y,
            { "Collision Point Y (m)", "cigi.coll_det_seg_response.collision_y",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Y component of a vector, which lies along the defined segment where the segment intersected a surface", HFILL }
        },
        { &hf_cigi2_collision_detection_segment_response_collision_z,
            { "Collision Point Z (m)", "cigi.coll_det_seg_response.collision_z",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the Z component of a vector, which lies along the defined segment where the segment intersected a surface", HFILL }
        },

        /* CIGI2 Sensor Response */
        { &hf_cigi2_sensor_response,
            { "Sensor Response", "cigi.sensor_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Sensor Response Packet", HFILL }
        },
        { &hf_cigi2_sensor_response_view_id,
            { "View ID", "cigi.sensor_response.view_id",
                FT_UINT8, BASE_DEC, NULL, 0xf8,
                "Indicates the sensor view", HFILL }
        },
        { &hf_cigi2_sensor_response_status,
            { "Sensor Status", "cigi.sensor_response.status",
                FT_UINT8, BASE_DEC, VALS(cigi2_sensor_response_status_vals), 0x06,
                "Indicates the current sensor mode", HFILL }
        },
        { &hf_cigi2_sensor_response_sensor_id,
            { "Sensor ID", "cigi.sensor_response.sensor_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the sensor response corresponding to the associated sensor control data packet", HFILL }
        },
        { &hf_cigi2_sensor_response_x_offset,
            { "Gate X Offset (degrees)", "cigi.sensor_response.x_offset",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the target's horizontal offset from the view plane normal", HFILL }
        },
        { &hf_cigi2_sensor_response_y_offset,
            { "Gate Y Offset (degrees)", "cigi.sensor_response.y_offset",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the target's vertical offset from the view plane normal", HFILL }
        },
        { &hf_cigi2_sensor_response_x_size,
            { "Gate X Size", "cigi.sensor_response.x_size",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the target size in the X direction (horizontal) in pixels", HFILL }
        },
        { &hf_cigi2_sensor_response_y_size,
            { "Gate Y Size", "cigi.sensor_response.y_size",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the target size in the Y direction (vertical) in pixels", HFILL }
        },

        /* CIGI3 Sensor Response */
        { &hf_cigi3_sensor_response,
            { "Sensor Response", "cigi.sensor_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Sensor Response Packet", HFILL }
        },
        { &hf_cigi3_sensor_response_view_id,
            { "View ID", "cigi.sensor_response.view_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the view that represents the sensor display", HFILL }
        },
        { &hf_cigi3_sensor_response_sensor_id,
            { "Sensor ID", "cigi.sensor_response.sensor_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the sensor to which the data in this packet apply", HFILL }
        },
        { &hf_cigi3_sensor_response_sensor_status,
            { "Sensor Status", "cigi.sensor_response.sensor_status",
                FT_UINT8, BASE_DEC, VALS(cigi3_sensor_response_sensor_status_vals), 0x03,
                "Indicates the current tracking state of the sensor", HFILL }
        },
        { &hf_cigi3_sensor_response_gate_x_size,
            { "Gate X Size (pixels or raster lines)", "cigi.sensor_response.gate_x_size",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the gate symbol size along the view's X axis", HFILL }
        },
        { &hf_cigi3_sensor_response_gate_y_size,
            { "Gate Y Size (pixels or raster lines)", "cigi.sensor_response.gate_y_size",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the gate symbol size along the view's Y axis", HFILL }
        },
        { &hf_cigi3_sensor_response_gate_x_pos,
            { "Gate X Position (degrees)", "cigi.sensor_response.gate_x_pos",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the gate symbol's position along the view's X axis", HFILL }
        },
        { &hf_cigi3_sensor_response_gate_y_pos,
            { "Gate Y Position (degrees)", "cigi.sensor_response.gate_y_pos",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the gate symbol's position along the view's Y axis", HFILL }
        },
        { &hf_cigi3_sensor_response_frame_ctr,
            { "Frame Counter", "cigi.sensor_response.frame_ctr",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Indicates the IG's frame counter at the time that the IG calculates the gate and line-of-sight intersection data", HFILL }
        },


        /* CIGI4 Sensor Response */

        /* CIGI3 Sensor Extended Response */
        { &hf_cigi3_sensor_extended_response,
            { "Sensor Extended Response", "cigi.sensor_ext_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Sensor Extended Response Packet", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_view_id,
            { "View ID", "cigi.sensor_ext_response.view_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the view that represents the sensor display", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_sensor_id,
            { "Sensor ID", "cigi.sensor_ext_response.sensor_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Specifies the sensor to which the data in this packet apply", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_sensor_status,
            { "Sensor Status", "cigi.sensor_ext_response.sensor_status",
                FT_UINT8, BASE_DEC, VALS(cigi3_sensor_extended_response_sensor_status_vals), 0x03,
                "Indicates the current tracking state of the sensor", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_entity_id_valid,
            { "Entity ID Valid", "cigi.sensor_ext_response.entity_id_valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x04,
                "Indicates whether the target is an entity or a non-entity object", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_entity_id,
            { "Entity ID", "cigi.sensor_ext_response.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity ID of the target", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_gate_x_size,
            { "Gate X Size (pixels or raster lines)", "cigi.sensor_ext_response.gate_x_size",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the gate symbol size along the view's X axis", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_gate_y_size,
            { "Gate Y Size (pixels or raster lines)", "cigi.sensor_ext_response.gate_y_size",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies the gate symbol size along the view's Y axis", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_gate_x_pos,
            { "Gate X Position (degrees)", "cigi.sensor_ext_response.gate_x_pos",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the gate symbol's position along the view's X axis", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_gate_y_pos,
            { "Gate Y Position (degrees)", "cigi.sensor_ext_response.gate_y_pos",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Specifies the gate symbol's position along the view's Y axis", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_frame_ctr,
            { "Frame Counter", "cigi.sensor_ext_response.frame_ctr",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Indicates the IG's frame counter at the time that the IG calculates the gate and line-of-sight intersection data", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_track_lat,
            { "Track Point Latitude (degrees)", "cigi.sensor_ext_response.track_lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the geodetic latitude of the point being tracked by the sensor", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_track_lon,
            { "Track Point Longitude (degrees)", "cigi.sensor_ext_response.track_lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the geodetic longitude of the point being tracked by the sensor", HFILL }
        },
        { &hf_cigi3_sensor_extended_response_track_alt,
            { "Track Point Altitude (m)", "cigi.sensor_ext_response.track_alt",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the geodetic altitude of the point being tracked by the sensor", HFILL }
        },


        /* CIGI4 Sensor Extended Response */

        /* CIGI2 Height of Terrain Response */
        { &hf_cigi2_height_of_terrain_response,
            { "Height of Terrain Response", "cigi.hot_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Height of Terrain Response Packet", HFILL }
        },
        { &hf_cigi2_height_of_terrain_response_hot_id,
            { "HOT ID", "cigi.hot_response.hot_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the HOT response corresponding to the associated HOT request", HFILL }
        },
        { &hf_cigi2_height_of_terrain_response_valid,
            { "Valid", "cigi.hot_response.valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x80,
                "Indicates whether the response is valid or invalid", HFILL }
        },
        { &hf_cigi2_height_of_terrain_response_material_type,
            { "Material Type", "cigi.hot_response.material_type",
                FT_INT32, BASE_DEC, NULL, 0x0,
                "Specifies the material type of the object intersected by the HOT test segment", HFILL }
        },
        { &hf_cigi2_height_of_terrain_response_alt,
            { "Altitude (m)", "cigi.hot_response.alt",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Represents the altitude of the terrain for the position requested in the HOT request data packet", HFILL }
        },

        /* CIGI2 Collision Detection Volume Response */
        { &hf_cigi2_collision_detection_volume_response,
            { "Collision Detection Volume Response", "cigi.coll_det_vol_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Collision Detection Volume Response Packet", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_response_entity_id,
            { "Entity ID", "cigi.coll_det_vol_response.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates which entity experienced a collision", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_response_volume_id,
            { "Volume ID", "cigi.coll_det_vol_response.volume_id",
                FT_UINT8, BASE_DEC, NULL, 0xfe,
                "Identifies the collision volume corresponding to the associated Collision Detection Volume Request", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_response_contact,
            { "Entity/Non-Entity Contact", "cigi.coll_det_vol_response.contact",
                FT_BOOLEAN, 8, TFS(&cigi2_collision_detection_volume_response_contact_tfs), 0x01,
                "Indicates whether another entity was contacted during this collision", HFILL }
        },
        { &hf_cigi2_collision_detection_volume_response_contact_entity,
            { "Contacted Entity ID", "cigi.coll_det_vol_response.contact_entity",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates which entity was contacted with during the collision", HFILL }
        },

        /* CIGI3 Position Response */
        { &hf_cigi3_position_response,
            { "Position Response", "cigi.pos_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Position Response Packet", HFILL }
        },
        { &hf_cigi3_position_response_object_id,
            { "Object ID", "cigi.pos_response.object_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Identifies the entity, view, view group, or motion tracking device whose position is being reported", HFILL }
        },
        { &hf_cigi3_position_response_part_id,
            { "Articulated Part ID", "cigi.pos_response.part_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the articulated part whose position is being reported", HFILL }
        },
        { &hf_cigi3_position_response_object_class,
            { "Object Class", "cigi.pos_response.object_class",
                FT_UINT8, BASE_DEC, VALS(cigi3_position_response_object_class_vals), 0x07,
                "Indicates the type of object whose position is being reported", HFILL }
        },
        { &hf_cigi3_position_response_coord_system,
            { "Coordinate System", "cigi.pos_response.coord_system",
                FT_UINT8, BASE_DEC, VALS(cigi3_position_response_coord_system_vals), 0x18,
                "Indicates the coordinate system in which the position and orientation are specified", HFILL }
        },
        { &hf_cigi3_position_response_lat_xoff,
            { "Latitude (degrees)/X Offset (m)", "cigi.pos_response.lat_xoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the geodetic latitude of the entity, articulated part, view, or view group or indicates the X offset from the parent entity's origin to the child entity, articulated part, view or view group", HFILL }
        },
        { &hf_cigi3_position_response_lon_yoff,
            { "Longitude (degrees)/Y Offset (m)", "cigi.pos_response.lon_yoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the geodetic longitude of the entity, articulated part, view, or view group or indicates the Y offset from the parent entity's origin to the child entity, articulated part, view, or view group", HFILL }
        },
        { &hf_cigi3_position_response_alt_zoff,
            { "Altitude (m)/Z Offset (m)", "cigi.pos_response.alt_zoff",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                "Indicates the geodetic altitude of the entity, articulated part, view, or view group or indicates the Z offset from the parent entity's origin to the child entity, articulated part, view, or view group", HFILL }
        },
        { &hf_cigi3_position_response_roll,
            { "Roll (degrees)", "cigi.pos_response.roll",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the roll angle of the specified entity, articulated part, view, or view group", HFILL }
        },
        { &hf_cigi3_position_response_pitch,
            { "Pitch (degrees)", "cigi.pos_response.pitch",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the pitch angle of the specified entity, articulated part, view, or view group", HFILL }
        },
        { &hf_cigi3_position_response_yaw,
            { "Yaw (degrees)", "cigi.pos_response.yaw",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the yaw angle of the specified entity, articulated part, view, or view group", HFILL }
        },


        /* CIGI4 Position Response */

        /* CIGI3 Weather Conditions Response */
        { &hf_cigi3_weather_conditions_response,
            { "Weather Conditions Response", "cigi.wea_cond_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Weather Conditions Response Packet", HFILL }
        },
        { &hf_cigi3_weather_conditions_response_request_id,
            { "Request ID", "cigi.wea_cond_response.request_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the environmental conditions request to which this response packet corresponds", HFILL }
        },
        { &hf_cigi3_weather_conditions_response_humidity,
            { "Humidity (%)", "cigi.wea_cond_response.humidity",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the humidity at the request location", HFILL }
        },
        { &hf_cigi3_weather_conditions_response_air_temp,
            { "Air Temperature (degrees C)", "cigi.wea_cond_response.air_temp",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the air temperature at the requested location", HFILL }
        },
        { &hf_cigi3_weather_conditions_response_visibility_range,
            { "Visibility Range (m)", "cigi.wea_cond_response.visibility_range",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the visibility range at the requested location", HFILL }
        },
        { &hf_cigi3_weather_conditions_response_horiz_speed,
            { "Horizontal Wind Speed (m/s)", "cigi.wea_cond_response.horiz_speed",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the local wind speed parallel to the ellipsoid-tangential reference plane", HFILL }
        },
        { &hf_cigi3_weather_conditions_response_vert_speed,
            { "Vertical Wind Speed (m/s)", "cigi.wea_cond_response.vert_speed",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the local vertical wind speed", HFILL }
        },
        { &hf_cigi3_weather_conditions_response_wind_direction,
            { "Wind Direction (degrees)", "cigi.wea_cond_response.wind_direction",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the local wind direction", HFILL }
        },
        { &hf_cigi3_weather_conditions_response_barometric_pressure,
            { "Barometric Pressure (mb or hPa)", "cigi.wea_cond_response.barometric_pressure",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the atmospheric pressure at the requested location", HFILL }
        },

        /* CIGI4 Weather Conditions Response */

        /* CIGI3 Aerosol Concentration Response */
        { &hf_cigi3_aerosol_concentration_response,
            { "Aerosol Concentration Response", "cigi.aerosol_concentration_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Aerosol Concentration Response Packet", HFILL }
        },
        { &hf_cigi3_aerosol_concentration_response_request_id,
            { "Request ID", "cigi.aerosol_concentration_response.request_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the environmental conditions request to which this response packet corresponds", HFILL }
        },
        { &hf_cigi3_aerosol_concentration_response_layer_id,
            { "Layer ID", "cigi.aerosol_concentration_response.layer_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the weather layer whose aerosol concentration is being described", HFILL }
        },
        { &hf_cigi3_aerosol_concentration_response_aerosol_concentration,
            { "Aerosol Concentration (g/m^3)", "cigi.aerosol_concentration_response.aerosol_concentration",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Identifies the concentration of airborne particles", HFILL }
        },

        /* CIGI4 Aerosol Concentration Response */

        /* CIGI3 Maritime Surface Conditions Response */
        { &hf_cigi3_maritime_surface_conditions_response,
            { "Maritime Surface Conditions Response", "cigi.maritime_surface_conditions_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Maritime Surface Conditions Response Packet", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_response_request_id,
            { "Request ID", "cigi.maritime_surface_conditions_response.request_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the environmental conditions request to which this response packet corresponds", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_response_sea_surface_height,
            { "Sea Surface Height (m)", "cigi.maritime_surface_conditions_response.sea_surface_height",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the height of the sea surface at equilibrium", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_response_surface_water_temp,
            { "Surface Water Temperature (degrees C)", "cigi.maritime_surface_conditions_response.surface_water_temp",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the water temperature at the sea surface", HFILL }
        },
        { &hf_cigi3_maritime_surface_conditions_response_surface_clarity,
            { "Surface Clarity (%)", "cigi.maritime_surface_conditions_response.surface_clarity",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the clarity of the water at its surface", HFILL }
        },

        /* CIGI4 Maritime Surface Conditions Response */

        /* CIGI3 Terrestrial Surface Conditions Response */
        { &hf_cigi3_terrestrial_surface_conditions_response,
            { "Terrestrial Surface Conditions Response", "cigi.terr_surface_cond_response",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Terrestrial Surface Conditions Response Packet", HFILL }
        },
        { &hf_cigi3_terrestrial_surface_conditions_response_request_id,
            { "Request ID", "cigi.terr_surface_cond_response.request_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Identifies the environmental conditions request to which this response packet corresponds", HFILL }
        },
        { &hf_cigi3_terrestrial_surface_conditions_response_surface_id,
            { "Surface Condition ID", "cigi.terr_surface_cond_response.surface_id",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Indicates the presence of a specific surface condition or contaminant at the test point", HFILL }
        },

        /* CIGI4 Terrestrial Surface Conditions Response */

        /* CIGI3 Collision Detection Segment Notification */
        { &hf_cigi3_collision_detection_segment_notification,
            { "Collision Detection Segment Notification", "cigi.coll_det_seg_notification",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Collision Detection Segment Notification Packet", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_notification_entity_id,
            { "Entity ID", "cigi.coll_det_seg_notification.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity to which the collision detection segment belongs", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_notification_segment_id,
            { "Segment ID", "cigi.coll_det_seg_notification.segment_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the ID of the collision detection segment along which the collision occurred", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_notification_type,
            { "Collision Type", "cigi.coll_det_seg_notification.type",
                FT_BOOLEAN, 8, TFS(&cigi3_collision_detection_segment_notification_type_tfs), 0x01,
                "Indicates whether the collision occurred with another entity or with a non-entity object", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_notification_contacted_entity_id,
            { "Contacted Entity ID", "cigi.coll_det_seg_notification.contacted_entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity with which the collision occurred", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_notification_material_code,
            { "Material Code", "cigi.coll_det_seg_notification.material_code",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Indicates the material code of the surface at the point of collision", HFILL }
        },
        { &hf_cigi3_collision_detection_segment_notification_intersection_distance,
            { "Intersection Distance (m)", "cigi.coll_det_seg_notification.intersection_distance",
                FT_FLOAT, BASE_NONE, NULL, 0x0,
                "Indicates the distance along the collision test vector from the source endpoint to the point of intersection", HFILL }
        },

        /* CIGI4 Collision Detection Segment Notification */

        /* CIGI3 Collision Detection Volume Notification */
        { &hf_cigi3_collision_detection_volume_notification,
            { "Collision Detection Volume Notification", "cigi.coll_det_vol_notification",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Collision Detection Volume Notification Packet", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_notification_entity_id,
            { "Entity ID", "cigi.coll_det_vol_notification.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity to which the collision detection volume belongs", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_notification_volume_id,
            { "Volume ID", "cigi.coll_det_vol_notification.volume_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the ID of the collision detection volume within which the collision occurred", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_notification_type,
            { "Collision Type", "cigi.coll_det_vol_notification.type",
                FT_BOOLEAN, 8, TFS(&cigi3_collision_detection_volume_notification_type_tfs), 0x01,
                "Indicates whether the collision occurred with another entity or with a non-entity object", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_notification_contacted_entity_id,
            { "Contacted Entity ID", "cigi.coll_det_vol_notification.contacted_entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity with which the collision occurred", HFILL }
        },
        { &hf_cigi3_collision_detection_volume_notification_contacted_volume_id,
            { "Contacted Volume ID", "cigi.coll_det_vol_notification.contacted_volume_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Indicates the ID of the collision detection volume with which the collision occurred", HFILL }
        },

        /* CIGI4 Collision Detection Volume Notification */

        /* CIGI3 Animation Stop Notification */
        { &hf_cigi3_animation_stop_notification,
            { "Animation Stop Notification", "cigi.animation_stop_notification",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Animation Stop Notification Packet", HFILL }
        },
        { &hf_cigi3_animation_stop_notification_entity_id,
            { "Entity ID", "cigi.animation_stop_notification.entity_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates the entity ID of the animation that has stopped", HFILL }
        },

        /* CIGI4 Animation Stop Notification */

        /* CIGI3 Event Notification */
        { &hf_cigi3_event_notification,
            { "Event Notification", "cigi.event_notification",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Event Notification Packet", HFILL }
        },
        { &hf_cigi3_event_notification_event_id,
            { "Event ID", "cigi.event_notification.event_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Indicates which event has occurred", HFILL }
        },
        { &hf_cigi3_event_notification_data_1,
            { "Event Data 1", "cigi.event_notification.data_1",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Used for user-defined event data", HFILL }
        },
        { &hf_cigi3_event_notification_data_2,
            { "Event Data 2", "cigi.event_notification.data_2",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Used for user-defined event data", HFILL }
        },
        { &hf_cigi3_event_notification_data_3,
            { "Event Data 3", "cigi.event_notification.data_3",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Used for user-defined event data", HFILL }
        },

        /* CIGI4 Event Notification */

        /* CIGI2 Image Generator Message */
        { &hf_cigi2_image_generator_message,
            { "Image Generator Message", "cigi.image_generator_message",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Image Generator Message Packet", HFILL }
        },
        { &hf_cigi2_image_generator_message_id,
            { "Message ID", "cigi.image_generator_message.message_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Uniquely identifies an instance of an Image Generator Response Message", HFILL }
        },
        { &hf_cigi2_image_generator_message_message,
            { "Message", "cigi.image_generator_message.message",
                FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
                "Image generator message", HFILL }
        },

        /* CIGI3 Image Generator Message */
        { &hf_cigi3_image_generator_message,
            { "Image Generator Message", "cigi.image_generator_message",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Image Generator Message Packet", HFILL }
        },
        { &hf_cigi3_image_generator_message_id,
            { "Message ID", "cigi.image_generator_message.message_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Specifies a numerical identifier for the message", HFILL }
        },
        { &hf_cigi3_image_generator_message_message,
            { "Message", "cigi.image_generator_message.message",
                FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
                "Message string", HFILL }
        },

        /* CIGI4 Image Generator Message */

        /* CIGI2 User Definable */
        { &hf_cigi2_user_definable,
            { "User Definable", "cigi.user_definable",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "User definable packet", HFILL }
        },

        /* CIGI3 User-Defined Packets */
        { &hf_cigi3_user_defined,
            { "User-Defined", "cigi.user_defined",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "User-Defined Packet", HFILL }
        },

        /* CIGI4 locally Defined Packets */
        { &hf_cigi4_locally_defined,
            { "locally-Defined", "cigi.locally_defined",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "locally-Defined Packet", HFILL }
        },

        /* CIGI4 Registered Packets */
        { &hf_cigi4_registered,
            { "Registered", "cigi.registered",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Registered Packet", HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_cigi_invalid_len,
            { "cigi.invalid_len", PI_MALFORMED, PI_ERROR,
                "Packet offset does not match packet length",
                EXPFILL }}
    };

    /* CIGI preferences */
    static const enum_val_t cigi_versions[] = {
        { "from_packet", "From Packet", CIGI_VERSION_FROM_PACKET },
        { "cigi2", "CIGI 2", CIGI_VERSION_2 },
        { "cigi3", "CIGI 3", CIGI_VERSION_3 },
        { "cigi4", "CIGI 4", CIGI_VERSION_4 },
        { NULL, NULL, 0 }
    };

    static const enum_val_t cigi_byte_orders[] = {
        { "from_packet", "From Packet", CIGI_BYTE_ORDER_FROM_PACKET },
        { "big_endian", "Big-Endian", CIGI_BYTE_ORDER_BIG_ENDIAN },
        { "little_endian", "Little-Endian", CIGI_BYTE_ORDER_LITTLE_ENDIAN },
        { NULL, NULL, 0 }
    };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_cigi,
        &ett_cigi4_start_of_frame_flags,
        &ett_cigi4_start_of_frame_ig_condition_flags,
        &ett_cigi4_ig_control_entity_substitution,
        &ett_cigi4_ig_control_flags,
        &ett_cigi4_entity_position_flags,
        &ett_cigi4_hat_hot_request_flags,
        &ett_cigi4_hat_hot_response_flags,
        &ett_cigi4_hat_hot_extended_response_flags,
        &ett_cigi4_articulated_part_control_part_enable_flags,
        &ett_cigi4_short_articulated_part_control_part_enable_flags,
        &ett_cigi4_velocity_control_flags,
        &ett_cigi4_celestial_sphere_control_flags,
        &ett_cigi4_view_control_enable_flags,
        &ett_cigi4_symbol_circle_definition_circles,
        &ett_cigi4_symbol_polygon_definition_vertices,
        &ett_cigi4_symbol_circle_textured_definition_circles,
        &ett_cigi4_symbol_polygon_textured_definition_vertices
    };

    /* Register the protocol name and description */
    proto_cigi = proto_register_protocol("Common Image Generator Interface",
            "CIGI", "cigi");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_cigi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_cigi = expert_register_protocol(proto_cigi);
    expert_register_field_array(expert_cigi, ei, array_length(ei));

    /* Register preferences module */
    cigi_module = prefs_register_protocol(proto_cigi, proto_reg_handoff_cigi);

    /* Register preferences */
    prefs_register_enum_preference(cigi_module, "version", "CIGI version", "The version of CIGI with which to dissect packets", &global_cigi_version, cigi_versions, false);
    prefs_register_enum_preference(cigi_module, "byte_order", "Byte Order", "The byte order with which to dissect CIGI packets (CIGI3)", &global_cigi_byte_order, cigi_byte_orders, false);
    prefs_register_string_preference(cigi_module, "host", "Host IP", "IPv4 address or hostname of the host", &global_host_ip);
    prefs_register_string_preference(cigi_module, "ig", "Image Generator IP", "IPv4 address or hostname of the image generator", &global_ig_ip);

    /* Register the dissector */
    cigi_handle = register_dissector("cigi", dissect_cigi, proto_cigi);

    cigi3_packet_id_table = register_dissector_table("cigi3.packet_id", "CIGI3 Packet ID",
            proto_cigi, FT_UINT8, BASE_DEC);

    cigi4_packet_id_table = register_dissector_table("cigi4.packet_id", "CIGI4 Packet ID",
        proto_cigi, FT_UINT16, BASE_HEX);
}

/* This function is also called by preferences whenever "Apply" is pressed
   (see prefs_register_protocol above) so it should accommodate being called
   more than once.
*/
void
proto_reg_handoff_cigi(void)
{
    static bool inited = false;

    /* If the CIGI version preference was changed update the cigi version
     * information for all packets */
    if ( global_cigi_version != CIGI_VERSION_FROM_PACKET ) {
        cigi_version = global_cigi_version;
    }

    /* If the CIGI byte order preference was changed update the cigi byte
     * order information for all packets */
    switch ( global_cigi_byte_order ) {

    case CIGI_BYTE_ORDER_BIG_ENDIAN:
        cigi_byte_order = ENC_BIG_ENDIAN;
        break;

    case CIGI_BYTE_ORDER_LITTLE_ENDIAN:
        cigi_byte_order = ENC_LITTLE_ENDIAN;
        break;

    default:  /* includes CIGI_BYTE_ORDER_FROM_PACKET */
        /* Leave it alone. */
        break;
    }

    if( !inited ) {
        dissector_add_for_decode_as_with_preference("udp.port", cigi_handle);
        dissector_add_for_decode_as_with_preference("tcp.port", cigi_handle);
        heur_dissector_add("udp", dissect_cigi_heur, "CIGI over UDP", "cigi_udp", proto_cigi, HEURISTIC_ENABLE);

        // CIGI 3 packet ID types (some with fields added in 3.2 or 3.3).
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_IG_CONTROL,
            create_dissector_handle(cigi3_add_ig_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_ENTITY_CONTROL,
            create_dissector_handle(cigi3_add_entity_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_CONFORMAL_CLAMPED_ENTITY_CONTROL,
            create_dissector_handle(cigi3_add_conformal_clamped_entity_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_COMPONENT_CONTROL,
            create_dissector_handle(cigi3_add_component_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SHORT_COMPONENT_CONTROL,
            create_dissector_handle(cigi3_add_short_component_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_ARTICULATED_PART_CONTROL,
            create_dissector_handle(cigi3_add_articulated_part_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SHORT_ARTICULATED_PART_CONTROL,
            create_dissector_handle(cigi3_add_short_articulated_part_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_RATE_CONTROL,
            create_dissector_handle(cigi3_add_rate_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_CELESTIAL_SPHERE_CONTROL,
            create_dissector_handle(cigi3_add_celestial_sphere_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_ATMOSPHERE_CONTROL,
            create_dissector_handle(cigi3_add_atmosphere_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_ENVIRONMENTAL_REGION_CONTROL,
            create_dissector_handle(cigi3_add_environmental_region_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_WEATHER_CONTROL,
            create_dissector_handle(cigi3_add_weather_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_MARITIME_SURFACE_CONDITIONS_CONTROL,
            create_dissector_handle(cigi3_add_maritime_surface_conditions_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_WAVE_CONTROL,
            create_dissector_handle(cigi3_add_wave_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL,
            create_dissector_handle(cigi3_add_terrestrial_surface_conditions_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_VIEW_CONTROL,
            create_dissector_handle(cigi3_add_view_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SENSOR_CONTROL,
            create_dissector_handle(cigi3_add_sensor_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_MOTION_TRACKER_CONTROL,
            create_dissector_handle(cigi3_add_motion_tracker_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_EARTH_REFERENCE_MODEL_DEFINITION,
            create_dissector_handle(cigi3_add_earth_reference_model_definition, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_TRAJECTORY_DEFINITION,
            create_dissector_handle(cigi3_add_trajectory_definition, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_VIEW_DEFINITION,
            create_dissector_handle(cigi3_add_view_definition, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION,
            create_dissector_handle(cigi3_add_collision_detection_segment_definition, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION,
            create_dissector_handle(cigi3_add_collision_detection_volume_definition, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_HAT_HOT_REQUEST,
            create_dissector_handle(cigi3_add_hat_hot_request, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_LINE_OF_SIGHT_SEGMENT_REQUEST,
            create_dissector_handle(cigi3_add_line_of_sight_segment_request, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_LINE_OF_SIGHT_VECTOR_REQUEST,
            create_dissector_handle(cigi3_add_line_of_sight_vector_request, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_POSITION_REQUEST,
            create_dissector_handle(cigi3_add_position_request, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_ENVIRONMENTAL_CONDITIONS_REQUEST,
            create_dissector_handle(cigi3_add_environmental_conditions_request, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_START_OF_FRAME,
            create_dissector_handle(cigi3_add_start_of_frame, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_HAT_HOT_RESPONSE,
            create_dissector_handle(cigi3_add_hat_hot_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_HAT_HOT_EXTENDED_RESPONSE,
            create_dissector_handle(cigi3_add_hat_hot_extended_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_LINE_OF_SIGHT_RESPONSE,
            create_dissector_handle(cigi3_add_line_of_sight_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_LINE_OF_SIGHT_EXTENDED_RESPONSE,
            create_dissector_handle(cigi3_add_line_of_sight_extended_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SENSOR_RESPONSE,
            create_dissector_handle(cigi3_add_sensor_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SENSOR_EXTENDED_RESPONSE,
            create_dissector_handle(cigi3_add_sensor_extended_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_POSITION_RESPONSE,
            create_dissector_handle(cigi3_add_position_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_WEATHER_CONDITIONS_RESPONSE,
            create_dissector_handle(cigi3_add_weather_conditions_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_AEROSOL_CONCENTRATION_RESPONSE,
            create_dissector_handle(cigi3_add_aerosol_concentration_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_MARITIME_SURFACE_CONDITIONS_RESPONSE,
            create_dissector_handle(cigi3_add_maritime_surface_conditions_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE,
            create_dissector_handle(cigi3_add_terrestrial_surface_conditions_response, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_COLLISION_DETECTION_SEGMENT_NOTIFICATION,
            create_dissector_handle(cigi3_add_collision_detection_segment_notification, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_COLLISION_DETECTION_VOLUME_NOTIFICATION,
            create_dissector_handle(cigi3_add_collision_detection_volume_notification, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_ANIMATION_STOP_NOTIFICATION,
            create_dissector_handle(cigi3_add_animation_stop_notification, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_EVENT_NOTIFICATION,
            create_dissector_handle(cigi3_add_event_notification, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_IMAGE_GENERATOR_MESSAGE,
            create_dissector_handle(cigi3_add_image_generator_message, proto_cigi));

        // Packet ID types added in CIGI 3.3
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SYMBOL_SURFACE_DEFINITION,
            create_dissector_handle(cigi3_3_add_symbol_surface_definition, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SYMBOL_TEXT_DEFINITION,
            create_dissector_handle(cigi3_3_add_symbol_text_definition, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SYMBOL_CIRCLE_DEFINITION,
            create_dissector_handle(cigi3_3_add_symbol_circle_definition, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SYMBOL_LINE_DEFINITION,
            create_dissector_handle(cigi3_3_add_symbol_line_definition, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SYMBOL_CLONE,
            create_dissector_handle(cigi3_3_add_symbol_clone, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SYMBOL_CONTROL,
            create_dissector_handle(cigi3_3_add_symbol_control, proto_cigi));
        dissector_add_uint("cigi3.packet_id", CIGI3_PACKET_ID_SHORT_SYMBOL_CONTROL,
            create_dissector_handle(cigi3_3_add_short_symbol_control, proto_cigi));

        // CIGI 4 packet ID types
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_IG_CONTROL,
            create_dissector_handle(cigi4_add_ig_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_ENTITY_POSITION,
            create_dissector_handle(cigi4_add_entity_position, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_CONFORMAL_CLAMPED_ENTITY_POSITION,
            create_dissector_handle(cigi4_add_conformal_clamped_entity_position, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_COMPONENT_CONTROL,
            create_dissector_handle(cigi4_add_component_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SHORT_COMPONENT_CONTROL,
            create_dissector_handle(cigi4_add_short_component_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_ARTICULATED_PART_CONTROL,
            create_dissector_handle(cigi4_add_articulated_part_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SHORT_ARTICULATED_PART_CONTROL,
            create_dissector_handle(cigi4_add_short_articulated_part_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_VELOCITY_CONTROL,
            create_dissector_handle(cigi4_add_velocity_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_CELESTIAL_SPHERE_CONTROL,
            create_dissector_handle(cigi4_add_celestial_sphere_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_ATMOSPHERE_CONTROL,
            create_dissector_handle(cigi4_add_atmosphere_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_ENVIRONMENTAL_REGION_CONTROL,
            create_dissector_handle(cigi4_add_environmental_region_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_WEATHER_CONTROL,
            create_dissector_handle(cigi4_add_weather_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_MARITIME_SURFACE_CONDITIONS_CONTROL,
            create_dissector_handle(cigi4_add_maritime_surface_conditions_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_WAVE_CONTROL,
            create_dissector_handle(cigi4_add_wave_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_CONTROL,
            create_dissector_handle(cigi4_add_terrestrial_surface_conditions_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_VIEW_CONTROL,
            create_dissector_handle(cigi4_add_view_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SENSOR_CONTROL,
            create_dissector_handle(cigi4_add_sensor_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_MOTION_TRACKER_CONTROL,
            create_dissector_handle(cigi4_add_motion_tracker_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_EARTH_REFERENCE_MODEL_DEFINITION,
            create_dissector_handle(cigi4_add_earth_reference_model_definition, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_ACCELERATION_CONTROL,
            create_dissector_handle(cigi4_add_acceleration_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_VIEW_DEFINITION,
            create_dissector_handle(cigi4_add_view_definition, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_COLLISION_DETECTION_SEGMENT_DEFINITION,
            create_dissector_handle(cigi4_add_collision_detection_segment_definition, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_COLLISION_DETECTION_VOLUME_DEFINITION,
            create_dissector_handle(cigi4_add_collision_detection_volume_definition, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_HAT_HOT_REQUEST,
            create_dissector_handle(cigi4_add_hat_hot_request, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_LINE_OF_SIGHT_SEGMENT_REQUEST,
            create_dissector_handle(cigi4_add_line_of_sight_segment_request, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_LINE_OF_SIGHT_VECTOR_REQUEST,
            create_dissector_handle(cigi4_add_line_of_sight_vector_request, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_POSITION_REQUEST,
            create_dissector_handle(cigi4_add_position_request, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_ENVIRONMENTAL_CONDITIONS_REQUEST,
            create_dissector_handle(cigi4_add_environmental_conditions_request, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SYMBOL_SURFACE_DEFINITION,
            create_dissector_handle(cigi4_add_symbol_surface_definition, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SYMBOL_TEXT_DEFINITION,
            create_dissector_handle(cigi4_add_symbol_text_definition, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SYMBOL_CIRCLE_DEFINITION,
            create_dissector_handle(cigi4_add_symbol_circle_definition, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SYMBOL_POLYGON_DEFINITION,
            create_dissector_handle(cigi4_add_symbol_polygon_definition, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SYMBOL_CLONE,
            create_dissector_handle(cigi4_add_symbol_clone, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SYMBOL_CONTROL,
            create_dissector_handle(cigi4_add_symbol_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SHORT_SYMBOL_CONTROL,
            create_dissector_handle(cigi4_add_short_symbol_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SYMBOL_CIRCLE_TEXTURED_DEFINITION,
            create_dissector_handle(cigi4_add_symbol_circle_textured, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SYMBOL_POLYGON_TEXTURED_DEFINITION,
            create_dissector_handle(cigi4_add_symbol_polygon_textured, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_ENTITY_CONTROL,
            create_dissector_handle(cigi4_add_entity_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_ANIMATION_CONTROL,
            create_dissector_handle(cigi4_add_animation_control, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_START_OF_FRAME,
            create_dissector_handle(cigi4_add_start_of_frame, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_HAT_HOT_RESPONSE,
            create_dissector_handle(cigi4_add_hat_hot_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_HAT_HOT_EXTENDED_RESPONSE,
            create_dissector_handle(cigi4_add_hat_hot_extended_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_LINE_OF_SIGHT_RESPONSE,
            create_dissector_handle(cigi4_add_line_of_sight_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_LINE_OF_SIGHT_EXTENDED_RESPONSE,
            create_dissector_handle(cigi4_add_line_of_sight_extended_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SENSOR_RESPONSE,
            create_dissector_handle(cigi4_add_sensor_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_SENSOR_EXTENDED_RESPONSE,
            create_dissector_handle(cigi4_add_sensor_extended_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_POSITION_RESPONSE,
            create_dissector_handle(cigi4_add_position_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_WEATHER_CONDITIONS_RESPONSE,
            create_dissector_handle(cigi4_add_weather_conditions_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_AEROSOL_CONCENTRATION_RESPONSE,
            create_dissector_handle(cigi4_add_aerosol_concentration_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_MARITIME_SURFACE_CONDITIONS_RESPONSE,
            create_dissector_handle(cigi4_add_maritime_surface_conditions_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_TERRESTRIAL_SURFACE_CONDITIONS_RESPONSE,
            create_dissector_handle(cigi4_add_terrestrial_surface_conditions_response, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_COLLISION_DETECTION_SEGMENT_NOTIFICATION,
            create_dissector_handle(cigi4_add_collision_detection_segment_notification, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_COLLISION_DETECTION_VOLUME_NOTIFICATION,
            create_dissector_handle(cigi4_add_collision_detection_volume_notification, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_ANIMATION_STOP_NOTIFICATION,
            create_dissector_handle(cigi4_add_animation_stop_notification, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_EVENT_NOTIFICATION,
            create_dissector_handle(cigi4_add_event_notification, proto_cigi));
        dissector_add_uint("cigi4.packet_id", CIGI4_PACKET_ID_IMAGE_GENERATOR_MESSAGE,
            create_dissector_handle(cigi4_add_image_generator_message, proto_cigi));

        inited = true;
    }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

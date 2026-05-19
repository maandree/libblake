CPPFLAGS_BLAKE2XB = -DSUPPORT_BLAKE2XB

OBJ_BLAKE2B_2XB =\
	libblake_blake2b_digest.o\
	libblake_blake2b_digest_get_required_input_size.o\
	libblake_blake2b_update.o\
	libblake_blake2b_force_update.o\
	libblake_internal_blake2b_compress.o\
	libblake_internal_blake2b_output_digest.o

OBJ_BLAKE2XB =\
	libblake_blake2xb_digest.o\
	libblake_blake2xb_force_update.o\
	libblake_blake2xb_init.o\
	libblake_blake2xb_predigest.o\
	libblake_blake2xb_predigest_get_required_input_size.o\
	libblake_blake2xb_update.o\
	libblake_internal_blake2xb_init0.o

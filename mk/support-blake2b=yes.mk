CPPFLAGS_BLAKE2B = -DSUPPORT_BLAKE2B

OBJ_BLAKE2B_2XB =\
	libblake_blake2b_digest.o\
	libblake_blake2b_digest_get_required_input_size.o\
	libblake_blake2b_update.o\
	libblake_blake2b_force_update.o\
	libblake_internal_blake2b_compress.o\
	libblake_internal_blake2b_output_digest.o

OBJ_BLAKE2B =\
	libblake_blake2b_init.o

CPPFLAGS_BLAKE2S = -DSUPPORT_BLAKE2S

OBJ_BLAKE2S_2XS =\
	libblake_blake2s_digest.o\
	libblake_blake2s_digest_get_required_input_size.o\
	libblake_blake2s_update.o\
	libblake_blake2s_force_update.o\
	libblake_internal_blake2s_compress.o\
	libblake_internal_blake2s_output_digest.o

OBJ_BLAKE2S =\
	libblake_blake2s_init.o

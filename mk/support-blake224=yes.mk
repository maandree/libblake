CPPFLAGS_BLAKE224 = -DSUPPORT_BLAKE224

OBJ_BLAKE224 =\
	libblake_blake224_digest.o\
	libblake_blake224_init.o\
	libblake_blake224_init2.o\
	libblake_blake224_update.o

OBJ_BLAKES =\
	libblake_blake224_digest_get_required_input_size.o\
	libblake_internal_blakes_digest.o\
	libblake_internal_blakes_update.o

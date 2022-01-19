#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "libblake.h"

#define CHECK_HEX(UPPERCASE, X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, XA, XB, XC, XD, XE, XF)\
	check_hex(UPPERCASE, #X0#X1#X2#X3#X4#X5#X6#X7#X8#X9#XA#XB#XC#XD#XE#XF,\
	          (unsigned char []){0x##X0, 0x##X1, 0x##X2, 0x##X3, 0x##X4, 0x##X5, 0x##X6, 0x##X7,\
	                             0x##X8, 0x##X9, 0x##XA, 0x##XB, 0x##XC, 0x##XD, 0x##XE, 0x##XF}, 16)

static void
check_hex(int uppercase, const char *hex, const unsigned char *bin, size_t n)
{
	unsigned char buf_bin[512];
	char buf_hex[1025];
	int valid = 0;
	memset(buf_bin, 0, sizeof(buf_bin));
	memset(buf_hex, 0, sizeof(buf_hex));
	buf_hex[2 * n] = 1;
	libblake_encode_hex(bin, n, buf_hex, uppercase);
	if (buf_hex[2 * n] || strcmp(buf_hex, hex)) {
		fprintf(stderr, "libblake_encode_hex with uppercase=%i failed\n", uppercase);
		exit(1);
	}
	if (libblake_decode_hex(hex, SIZE_MAX, NULL, &valid) != n || !valid ||
	    libblake_decode_hex(hex, SIZE_MAX, buf_bin, &valid) != n || !valid ||
	    memcmp(buf_bin, bin, n)) {
		fprintf(stderr, "libblake_decode_hex failed\n");
		exit(1);
	}
}

static const char *
digest_blake1(int length, const void *msg, size_t msglen, size_t bits)
{
	static char hex[sizeof(LIBBLAKE_BLAKE512_OUTPUT_SIZE) * 2 + 1];
	unsigned char buf[LIBBLAKE_BLAKE512_OUTPUT_SIZE];
	size_t req;
	char *data;

#define DIGEST(BITS)\
	do {\
		struct libblake_blake##BITS##_state s##BITS;\
		req = libblake_blake##BITS##_digest_get_required_input_size(msglen, bits, NULL);\
		data = malloc(req);\
		memcpy(data, msg, msglen + bits / 8 + !!(bits & 7));\
		libblake_blake##BITS##_init(&s##BITS);\
		libblake_blake##BITS##_digest(&s##BITS, data, msglen, bits, NULL, buf);\
		libblake_encode_hex(buf, LIBBLAKE_BLAKE##BITS##_OUTPUT_SIZE, hex, 0);\
		free(data);\
	} while (0)

	if (length == 224)
		DIGEST(224);
	else if (length == 256)
		DIGEST(256);
	else if (length == 384)
		DIGEST(384);
	else if (length == 512)
		DIGEST(512);
	else
		abort();

#undef DIGEST

	return hex;
}

#define CHECK_BLAKE1_STR(LENGTH, MSG, EXPECTED)\
	failed |= !check_blake1_(LENGTH, "“"MSG"”", MSG, sizeof(MSG) - 1, 0, EXPECTED)
#define CHECK_BLAKE224_STR(MSG, EXPECTED) CHECK_BLAKE1_STR(224, MSG, EXPECTED)
#define CHECK_BLAKE256_STR(MSG, EXPECTED) CHECK_BLAKE1_STR(256, MSG, EXPECTED)
#define CHECK_BLAKE384_STR(MSG, EXPECTED) CHECK_BLAKE1_STR(384, MSG, EXPECTED)
#define CHECK_BLAKE512_STR(MSG, EXPECTED) CHECK_BLAKE1_STR(512, MSG, EXPECTED)

#if 0
# define CHECK_BLAKE1_HEX(LENGTH, MSG, EXPECTED)\
	failed |= !check_blake1_(LENGTH, "0x"MSG, buf, libblake_decode_hex(MSG, SIZE_MAX, buf, &(int){0}), 0, EXPECTED)
# define CHECK_BLAKE224_HEX(MSG, EXPECTED) CHECK_BLAKE1_HEX(224, MSG, EXPECTED)
# define CHECK_BLAKE256_HEX(MSG, EXPECTED) CHECK_BLAKE1_HEX(256, MSG, EXPECTED)
# define CHECK_BLAKE384_HEX(MSG, EXPECTED) CHECK_BLAKE1_HEX(384, MSG, EXPECTED)
# define CHECK_BLAKE512_HEX(MSG, EXPECTED) CHECK_BLAKE1_HEX(512, MSG, EXPECTED)
#endif

#define CHECK_BLAKE1_BITS(LENGTH, MSG, BITS, EXPECTED)\
	failed |= !check_blake1_(LENGTH, "0x"MSG, buf, libblake_decode_hex(MSG, SIZE_MAX, buf, &(int){0}), BITS, EXPECTED)
#define CHECK_BLAKE224_BITS(MSG, BITS, EXPECTED) CHECK_BLAKE1_BITS(224, MSG, BITS, EXPECTED)
#define CHECK_BLAKE256_BITS(MSG, BITS, EXPECTED) CHECK_BLAKE1_BITS(256, MSG, BITS, EXPECTED)
#define CHECK_BLAKE384_BITS(MSG, BITS, EXPECTED) CHECK_BLAKE1_BITS(384, MSG, BITS, EXPECTED)
#define CHECK_BLAKE512_BITS(MSG, BITS, EXPECTED) CHECK_BLAKE1_BITS(512, MSG, BITS, EXPECTED)

static int
check_blake1_(int length, const char *dispmsg, const void *msg, size_t msglen, size_t bits, const char *expected)
{
	const char *result;
	bits &= 7;
	msglen -= bits > 0;
	result = digest_blake1(length, msg, msglen, bits);
	if (strcasecmp(result, expected)) {
		fprintf(stderr, "BLAKE-%i failed for %s:\n", length, dispmsg);
		if (bits)
			fprintf(stderr, "\tLength:   %zu bytes and %zu bits\n", msglen, bits);
		fprintf(stderr, "\tResult:   %s\n", result);
		fprintf(stderr, "\tExpected: %s\n", expected);
		fprintf(stderr, "\n");
		return 0;
	}
	return 1;
}

static int
check_blake1(void)
{
	char buf[1025];
	int failed = 0;
	size_t bits;

	CHECK_BLAKE224_STR("", "7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed");
	CHECK_BLAKE256_STR("", "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a");
	CHECK_BLAKE384_STR("", "c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706");
	CHECK_BLAKE512_STR("", "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8");

	CHECK_BLAKE512_STR("The quick brown fox jumps over the lazy dog",
	                   "1f7e26f63b6ad25a0896fd978fd050a1766391d2fd0471a77afb975e5034b7ad2d9ccf8dfb47abbbe656e1b82fbc634ba42ce186e8dc5e1ce09a885d41f43451");

	CHECK_BLAKE512_STR("The quick brown fox jumps over the lazy dof",
	                   "a701c2a1f9baabd8b1db6b75aee096900276f0b86dc15d247ecc03937b370324a16a4ffc0c3a85cd63229cfa15c15f4ba6d46ae2e849ed6335e9ff43b764198a");

	bits = 1;
#define X(INPUT, EXPECT) CHECK_BLAKE224_BITS(INPUT, bits++, EXPECT)
	X("00", "615b9bd1077a8270d4f647799ffaaf87c03d72efd37e4947fcf01cca");
	X("C0", "6a829dca3a3d0d35762d7b0f9a2c8379c32415c87a8ad773fefec19f");
	X("C0", "5478a106aca2b539d5bd52db8b19717d436ca27c14ef99ed565bc4a7");
	X("80", "2b10ebc335731de6148ce84ed05a2685b9c274105c6aaf1dd59ef000");
	X("48", "a49e36fd01041a0a86eb12d7f110bf4ef798b686fff48e5abc6bc8b4");
	X("50", "57036a8ad47cb24e0f329ef991b571211f171bf86f546aa068577cb5");
	X("98", "82417e4fdb2b426d125415b10fe7dae7e944291f8daeb049b80e93a0");
	X("CC", "5e21c1e375c7bc822046fad96910c95031bd4262ada71b4c91052fea");
	X("9800", "30df15eb42922a41c1ef59102115d2f656e94f39fd1eeca115a9a07a");
	X("9D40", "5c6c22d948c98644057c9ad31107164ecda652f4c51abd8cc4652ee6");
	X("AA80", "276babfb45f0da4ddce7012d009122cdb974702cce1fcc83e0b254af");
	X("9830", "5dd804d86cc32084c81caea4ee5b472b2ba6e8c17eb2ff982e9e885b");
	X("5030", "e3d122c703be5ebca4ecc1860a8f50cff518c3984d3605f3c98bb52b");
	X("4D24", "35e05b766f7fcfb136e62cef59400b3e776f74e69a16912a9e7a9d78");
	X("CBDE", "227804938f7d63d96a54778f71bfb7421dcf056ddd78ab8b739a7a2e");
	X("41FB", "195707e8ce71fb91c2c82ccf78022609a598bd80c9a505ef035314db");
	X("4FF400", "86113100dd674ebf5d0c36b609d9ab8bbd8ecb5d54b0a5aaea9d5e1d");
	X("FD0440", "608997b3ae1483e0298a08d816029d112124743cde703dd0350edbe9");
	X("424D00", "89f898843d7ab0bb50ac8f6d1139e18aca0ef1d4e95b089ec2172685");
	X("3FDEE0", "280cee22ba45b2ff9dfa70462cd34c106a24842c6a247f74ade67158");
	X("335768", "780f1fb7fd80898a10e9c6d63d212372bf7f6b3cd6a6c231ee5daa9b");
	X("051E7C", "0296e4a199194d5b65aa40fb0ec33870e36daa3e2e962d2c5b6f3a99");
	X("717F8C", "1e95aa999a1a68c1c5191d2365664415344ed1673cb6c12a849abf0a");
	X("1F877C", "4239b4afa926f2269b117059dc0310033c9c85acea1a031f97cd4e2a");
	X("EB35CF80", "dfd3f804fbc9ad5805fc5b529c1d0564e96454710d0b21d561357ac5");
	X("B406C480", "e1fd87c6396d42e19713290547cc324268c27b7fa40398ed3797b148");
	X("CEE88040", "dfebe7b56e9247d4023cecda04c28e1fc4eb6049fa27a747f75d832d");
	X("C584DB70", "79737f20528fac047c7ea52a2a295bd7ce15087773747cb450be6874");
	X("53587BC8", "de42f62c6eeddc5bd80fdf52edcf64754d875bb2b214d5e715833270");
	X("69A305B0", "328a913d190fa087c58958a321138400e5a9e9a8983c9853c0b932ea");
	X("C9375ECE", "efa18a9d2ada4755c260482989442f21b8c5b2e09155517e201d269e");
	X("C1ECFDFC", "9cd80af6d0181b831e1879959f287735c9cbf5d1e480e7341266d6f0");
	X("8D73E8A280", "2849a31c29e378fa9eef77ad80043e822c70cde973cb99a4a7f21a07");
	X("06F2522080", "d9315ee5d1e33178363ddfdd7d595e0ba4a6d82522500e27ed3075ae");
	X("3EF6C36F20", "40663b7856cfb2d57987a85dbd76c447dcf582481912c9a373924127");
	X("0127A1D340", "61a5fdead981d711d72d3dc5cfe7f8c40916ce16a42a97cb7b8a016e");
	X("6A6AB6C210", "a63d8d4a5239c7132031c1ca6527ebe3e7d6d647124fafdf5f123de2");
	X("AF3175E160", "3e7c863db3e16c2350a44e161a2aa3810764cf523c62ab71999a9d24");
	X("B66609ED86", "e3b7ce19f60913cd5aa1d43bd92de285f72163e0f9453f4e5f21bf52");
	X("21F134AC57", "9e908983741757ff632c01f2b2c4d7f1ec8e642d112c212ba9739fd1");
	X("3DC2AADFFC80", "4e1a8c57c3713217530a5f667b37f6bc23939d2fb43dea9745f50068");
	X("9202736D2240", "a3c9ece5a71fed7c2e58bfd0b67fcf286668c2bcc31826c1b4cd6d59");
	X("F219BD629820", "f087f490d55044aa4d147f79d0f1e980fdba1d78cacb5999ff9e67ca");
	X("F3511EE2C4B0", "49da5bdbc1fe187a28cbd493f383108ff1c6bcd71b3fef2c742074a5");
	X("3ECAB6BF7720", "2143ed11184621cb64716a451688291bd0799574f2a28537885540be");
	X("CD62F688F498", "0874dba67485be94b9f5a500fade53c94622573059a7fd78f50d0309");
	X("C2CBAA33A9F8", "2e14b39f6de58b0fdd67b9c45eae6c3ff71a363defea06975410e25a");
	X("C6F50BB74E29", "6d6d952053aead200de9daa856c2993a7a7fa4a15b3924fb77dbb384");
	X("79F1B4CCC62A00", "ad93ea3f245493cf2b660d6f5fe82b8bfb0d3394854e88c2704c98c2");
#undef X

	bits = 1;
#define X(INPUT, EXPECT) CHECK_BLAKE256_BITS(INPUT, bits++, EXPECT)
	X("00", "81a10984912cd57c12e923b46142b2b434dfe1a0ef29c03de05555f9f2fee9b4");
	X("C0", "eae1614ea36088a8fd69a4614c2d98fada81134baa991aebfb743cd297669b01");
	X("C0", "4ac92b8903f7076563a6309eb9bd386807d28fe721fc8128af86e88967739443");
	X("80", "c575142b6e471398bf9fc90a5660bb97f24cb106443b76e22b58084e82667b5d");
	X("48", "45bc790b0180778efe9fd0381528ba9e9ec4460685375e1283e519e338b4c55d");
	X("50", "673acd73e1ea3c418e7707cf543155e9dc0c52c6d4aa8a9b0559680b06992d48");
	X("98", "46bf46a9db7079a34f1b2b4ceffc8236730c2b5ec2a9f0d105ab5b66be9f6fd8");
	X("CC", "e104256a2bc501f459d03fac96b9014f593e22d30f4de525fa680c3aa189eb4f");
	X("9800", "1088da8ca79a1498f7d4629654307d63715f26edf916c8fb8c09d2039d28c8bc");
	X("9D40", "1b34cb31b73d6966f038cdd3d93fe973776f9f4bd5bd9b1008ae105edc53add3");
	X("AA80", "6df64c36384f863cbed1ccf0a615c04b808b73f35131e3f95adfcb93e54e8df0");
	X("9830", "37e539c6dfb9c94bc392090a41ae4eca0fe3eff478ef401cf163a73486754ef4");
	X("5030", "10ec14653844b6cbda11d908680f27de195a00446b773eb64480168074fb9439");
	X("4D24", "8f9d0cb5d596260935d8057c260c218091ba666ac14b1a46f2d918484cfbe173");
	X("CBDE", "891837f7f166cd0603379a2803fe27fed35853f5c4b6feed0fc74b4502d6105c");
	X("41FB", "8f341148be7e354fdf38b693d8c6b4e0bd57301a734f6fd35cd85b8491c3ddcd");
	X("4FF400", "ddfc63311a6e1996b257af4ec0750bcbe400d7d507eea84aee9fc44b88127236");
	X("FD0440", "5b452b7b003fab1abe488ba0dca0a6f5945d797a94f52e93d6e921af1a157fc4");
	X("424D00", "6733ca84f1652ff5d5252d4affa42d3ebda3fbd21a9a8fc07297dad28df7273c");
	X("3FDEE0", "1e5c24058d33f16a7cef6ad102e3a19b59e595598dd4ddc2c9b8182abbb89b84");
	X("335768", "29a77b3fa2b97407791da3fa792e40555a2cae9fa85d559ba633ac2e817d6b5e");
	X("051E7C", "3ef17d53fb61fe2f543a935820f244e25cc8c0ae30d9774ff22427a3fb820d7a");
	X("717F8C", "b2224450512df4c070084e17f6c8a423c5e22a66a77f4eb5792418832dcb05a0");
	X("1F877C", "bc334d1069099f10c601883ac6f3e7e9787c6aa53171f76a21923cc5ad3ab937");
	X("EB35CF80", "7360eb4415d316866b8a748fcd90b7a014c6d62a18218a48cdf681538dcac8ec");
	X("B406C480", "9e4a8d15be6cfd06425f224035a90ccb5fc8bf92e4d315bc6efe3d9c93085943");
	X("CEE88040", "643cf377e140bb1f5d2710927c84ab23b0c258b6c0ab47da4b592180086c24d2");
	X("C584DB70", "94b4d7f4830fda2e6ba7346f38456d28346589dec8b7dc6e61e3ec3580243c5e");
	X("53587BC8", "2d7508d69c7fb9bfacf35fafc118840b8ad42fabae5f27adc9d74154f2e3a78a");
	X("69A305B0", "eec86da7600c3953f088084364b37a3d2bb6522876b82f9cf9cfed764746d53d");
	X("C9375ECE", "7ff30cb54acd2e019c3664c42f37002d67132098d313525e5bced93470d19a56");
	X("C1ECFDFC", "b672a16f53982bab1e77685b71c0a5f6703ffd46a1c834be69f614bd128d658e");
	X("8D73E8A280", "3b171d80684fcbb88067e7519e0af3ab3d378254d36633b3eb8585553717ecf0");
	X("06F2522080", "d71133d28291531730403dbc363bf3d5a4c3db80861b7c3afbc4c769fedfd3aa");
	X("3EF6C36F20", "2e9830df74711da1a21e815aa6ab37013ebded7de7088ae8d5fdb5174440fe0b");
	X("0127A1D340", "5ba9f0532fbd0b44f0f7efd9988aa2e062a813797c732242ea5239f571adfb0f");
	X("6A6AB6C210", "e03567eefd4e515a73999fac87deb90726bdc488f4be6aa8a974c7b4ee13fc65");
	X("AF3175E160", "238036d9eeb9b09d9c9703b484833cc88097f27e34b8a94bef9f5e121b6d5575");
	X("B66609ED86", "284e01f8b5604db347cd9d4ab95cc8d62d3640aeaf7502a2439fe780c598ba39");
	X("21F134AC57", "d9134b2899057a7d8d320cc99e3e116982bc99d3c69d260a7f1ed3da8be68d99");
	X("3DC2AADFFC80", "3e64d5852d9a09ea76007a7b159430c3715598017850ec288316e13b80fd61c7");
	X("9202736D2240", "95f5bcf07e8a6c02b26f9fe29a5deb7faa5c03ab0e6180239924f5d48c7125af");
	X("F219BD629820", "0fcf4c343c9d94bf3dea22069a28d23ff953bde89cd0dee4d1a521d4a302f8a3");
	X("F3511EE2C4B0", "c32364fa782462bc3a3af38e03fb4f052bd238ab756eaabdd5f8000006446184");
	X("3ECAB6BF7720", "511150cbab4c6be4d59d926b093a2d10fb6d9fb06169f47af2f1d75c07463428");
	X("CD62F688F498", "a08519ce60cfef0554e8cd1a4d3cbe82504fe97b8b933cfccff5faac85bc787b");
	X("C2CBAA33A9F8", "cc8eb0c743b2440399632474ba84980bebc9f6eedbbce3e31fdc497e0ba32d9d");
	X("C6F50BB74E29", "637923bd29a35aa3ecbbd2a50549fc32c14cf0fdcaf41c3194dd7414fd224815");
	X("79F1B4CCC62A00", "106cd7e18e3bd16353cf561411d87b609536856d57180155b60d7bc0a73b9d45");
#undef X

	bits = 1;
#define X(INPUT, EXPECT) CHECK_BLAKE384_BITS(INPUT, bits++, EXPECT)
	X("00", "1ffde9711b419d7c97dc142e7704d2ae61163f8a818c47938b978d6113949d8e7819b9699d497a3b289b8bb4415ffae7");
	X("C0", "195d771c302bb1ca0c9ac55a782cbe877bc0bc28016f735de68d7cf5fc1d0a99cc69a32cb0174fd2a97d5fcf46aafded");
	X("C0", "883b186d9372a04d585eb1eef1cd32ff8a7c061d5e396f05fd9d3d9d6033de757bfc3adf30b06d7fb02a875a2ac0db70");
	X("80", "91140c47ba7ef06fe6810acef4be65ad772576291778c6b5588b08fd48beeae4e70c3ac4abb9636a637e9a6359a19053");
	X("48", "f03566b78ead38d98f787c08f117817702d24d3bc8c663551393a1f2e6a079855434414789b34dd360df198eb00e67a2");
	X("50", "68eeca6e6550ece0662882bd36605eeabea74230171225b708c1a375c90e4a59fec2eff42eba07441dc1f48d39665bd6");
	X("98", "70bb604b0893b22e2f4e2fc0e9cfd725648c9ff217df8eee219a7a1cab3039158ff1ae3c8b2106165f00e3dac9301adb");
	X("CC", "a77e65c0c03ecb831dbcdd50a3c2bce300d55eac002a9c197095518d8514c0b578e3ecb7415291f99ede91d49197dd05");
	X("9800", "fdf53e189982aead4849b6fba84b9e84a7f4c38a580840344e4017819f30901ca333b12954ea811049e023f073a69ae2");
	X("9D40", "0afc73af8a4f8645cfb30ceab03c256cabf8088d5452c66a766159428de6050484f39b31cb4eebbcb2a06a8a7b0e4626");
	X("AA80", "7939c08121bcbdd2d87069a3f8feedc3e1eeaa7a140574afd126441f4ed9e32b783ca02f33bb454aa6d05494d4c9028d");
	X("9830", "a9045405bb39e7f6f89398160208d61f2f4ccbd5c688a6b67aa6eef78d00ef1ee8c6779b781b8603eaf585d475cd86d5");
	X("5030", "bcbc3cff50f0bd0f03c9dcba0296f7bd7a9e111361335cdd8cb47cc02fe6bcff01d3244c6b7141b77b4cbfc88d6cd320");
	X("4D24", "9bc5c48e85de4ea136072a53b31d964668175c378a424af4503a454637cd55fa091b2e1a005a6f308f18f5f2b90900a3");
	X("CBDE", "4f1eea4e836e12d8521bce58831481e80fec26d40fbef756e571c9cf1e1072008a2475fbdda6b1dc6ff09238f2675329");
	X("41FB", "e80a87362c9d39e2074ac135e2514b0cdf0001bfd8c35888d7ca8bbc4e918a157386524d41579e7fcd9c3c9a4f7a991a");
	X("4FF400", "28a0158d802b4e6ca90dbd9558140dada402b3fa3f556fc06ab9cd0e645a32eb1793d5ba321e8e6fcbaef6403ba5d4c3");
	X("FD0440", "cf58d202fc28371bca34f2698569a87d06633777c457312341ce3651259041feefd2fcabe1618ad24d4707292a2f2c63");
	X("424D00", "b0f5ab250b2f65cb9a6b200f6bc39ba74db8a5282fdd9e8d1bf87c733da89005fac37f40dcdb9b095a70a018392c3018");
	X("3FDEE0", "ffd7f9bf50dcca42c961bbc4fff717ab586e01968d606407ec610aa3d2462987af054c694474c7b5878dd7af5124c1dc");
	X("335768", "1f288d53346f74a9618c47f5a77a9e41aece4005037e3b6b908f6d0b4d8faaf148cc18ac1632b3362e1a78369edfc6f6");
	X("051E7C", "d5dbcb933c5cba8c1b355b6152a947051a71ea0a9ad295ab308afa39fdce8a07e9e0192a187df0ff9e089718534a7c46");
	X("717F8C", "c6c62993fb330dd106932569300a97ab54837fe5927adcd0a418fa24e01148d80de54ddc63dc58705c62be1ea4b3ee32");
	X("1F877C", "d67cfa1b09c8c050094ea018bb5ecd3ce0c02835325467a8fa79701f0ad6bbd4a34947bbaa2fc5f9379985ccd6a1dc0e");
	X("EB35CF80", "dfba2a0077e56cacb0df1be549dfe06c9828e1eef91b77d83acc0300c0c67db0e2594a4bd552c80f4a0d98fae44a860c");
	X("B406C480", "a20846d26c780b03d4d0fe15757d664111aaedc435af784ae85e1a1b25ca56c476b86351edc1ad3825667b86328678d3");
	X("CEE88040", "ee885ca24e330d26bde1b3ea640fd0af5ab1840697bd12d015fc515d219cdd2c13bb3429f374727ee632a1555fef1ca3");
	X("C584DB70", "243a3c6ad6fb97298c04200273cbe829c636daab73ea7abaaf1caff193e9dc9b7399ed859a46a6daba98ee9fd810cf00");
	X("53587BC8", "01c6579dd37e707e33ec4a0a768499f28be4e80ba4952e645faa07f09d507dec9e81ab2cf34c0318a34a0ac4af621655");
	X("69A305B0", "081633892d928cd7debc78ce70b0a82f8595cf32e1998b0298490b8799b26f76ed428d13ca4da02e504efda5a3379dca");
	X("C9375ECE", "24a2d2af040b31fc238abfb935fb0f699eaf97291b75d5a7eaaf542e19c7e486554c166962943b762f2818172bbcdee5");
	X("C1ECFDFC", "7a57c41d850b7ab51c6075aba299ff649fdaf08a4c37088ece73b21304b1072c21930cc34ac6b0fc5f27b95f4f389b26");
	X("8D73E8A280", "e1480a83839ab8747935690f1922e0f05e8f67239f7dced9cfd39a1678ee10febb4f7580bd803c66ec5584ef102a12db");
	X("06F2522080", "f386f8bdd36de67d43aeb976b2d57a9499b3796c1c37e6c7b133bf2545d7efcd21be6935425a5dfaa627ceec834400b6");
	X("3EF6C36F20", "311c0aafbb8e6729641d9bb12d0434614f5be6e0d3d27933e1469b0c662430de7153b2aab9c4085758099e6064d2f883");
	X("0127A1D340", "9933fe64ef4de19c78695186286831534f30721b82d031b9f938fb19b4c2cab1d4ac53f63f96a60cf172702f9305854e");
	X("6A6AB6C210", "094b79964b193bf655f91f76f4d3589eab2a902587f730ec76251b98d9de4db846d81c29dba5eb20ede52db447f429a7");
	X("AF3175E160", "e05997f725613d05ec2a3edab5b9af53de9eeaef986ad4ed1f83c6c4211bb0b1a6058d8eaed94d52299e2e32225e2545");
	X("B66609ED86", "c0b0e332a81821d4dd06a72ef108fae9060f2c826b3905db037ad75db15efac9c04d0f284aae722e407b41f132a75980");
	X("21F134AC57", "324155f4f5e346bfe0b08e9642bebe86505795be186146d30242273ebebb3d51e076b1105ab647c130e6efc0b75072a7");
	X("3DC2AADFFC80", "4202b2a7fd50f9f64268a5cecaa979e68fb5e5b4f16050baa0eee6254640a243f8f775c44f26c0d950498c8f1bbb34cb");
	X("9202736D2240", "18987d9b924db295acb2645618b772fa7d451ef841f207d525c2c501e472fafb44b3078537515ed39475743c7d2d04c2");
	X("F219BD629820", "b059cd3e9e615574d0f2bbe11522ed7c2243f070272880a5f58bd147985a24afbdf8be2cf139792b482b97bfc94d6788");
	X("F3511EE2C4B0", "028c6ea676b4ab01cbdf0918a90e507429ca7b926763dc26ced6f7a851923b91fd4ac6054cc7432139af954c3abe5a94");
	X("3ECAB6BF7720", "5f46d3abe50df2b402567f95468862ecfc91508019c85a190a3c3eb2f6a77e794835697987dc4bce0bd3ef2afb89a026");
	X("CD62F688F498", "444921bbc8e0dceb33e0b4660f2e09fc8a0d8254ae03327af448408b1dc9229c95253c3873f09a522f428899d23d6846");
	X("C2CBAA33A9F8", "b4a57910d5ef0113585fbe7f3a5ebd7a3e3ddc4e66bd42a8baed7c59134d3cdc36c70a4a39fa11449ff8adfe4da66cb8");
	X("C6F50BB74E29", "5ddb50068ca430bffae7e5a8bbcb2c59171743cce027c0ea937fa2b511848192af2aca98ead30b0850b4d2d1542decdb");
	X("79F1B4CCC62A00", "7c80a8320015dfc5143d1c6d60a4b51c6943208005aa5176300ecdfa728d5bb53c9817b33c934eca94332716458572dc");
#undef X

	bits = 1;
#define X(INPUT, EXPECT) CHECK_BLAKE512_BITS(INPUT, bits++, EXPECT)
	X("00", "f0a9b5b755802205fd1a1f56e7a03d7573d46e8ba5037517281560fbe6db03c174b00597fb4e1427747c7382fe63c6692f05a5e0841e99883cb7c272c2a62191");
	X("C0", "777e21c87839badde651fc37334f6d7cdc8316914e7cb76dab2efab90c62ef307e590936349b85041542f00d94d870633957699e818db79e1e064b0991a9cd1a");
	X("C0", "1ffb9a5c5c4c5a0cb91d806fc1398e8a49bdac2cfb549628c886bf388f5a6c6b0854bc9c68155502016592c3f0cd54ded83276463a2aed864436950d99244958");
	X("80", "32ff282bc8a43dc777ab74582fc2354f4294c6d634b25c4f2f606c72e10ae41ef7f9391f3533649ce73a0dc6b5d30497f655bb87ae45aeb03c50c96d4c5218ff");
	X("48", "783a1850bc31594e382e346351cc004572288f1a12d95b6b52fc47a071033efd7ad6fc0424c93b97708da15cf0482bb0afa1b289545ae6cbbcd2970611dabb46");
	X("50", "fc355cd7b2f3cec08f4fbf64f8d08394c04ea80e9a6c2920312f450183c537395a6202d2532ff35597a7c2ec719c4174f347a8cf795fd71d2933a7003ecb05d0");
	X("98", "85bb7f4b9119d4495805c6f5ad9d4eb5f9ee363c34741147483abd6dfd24336bd1a5fa566578f861ffaa0ad6c617491a378477d6dd3d8025ff2b9ce6cdfd0b12");
	X("CC", "4f0ef594f20172d23504873f596984c64c1583c7b2abb8d8786aa2aeeae1c46c744b61893d661b0733b76d1fe19257dd68e0ef05422ca25d058dfe6c33d68709");
	X("9800", "073cf7ed8216a6b27f882563986489d1c418874f2b797a9a0c5c95394f3a9dbeb7eb3e2e6598fa5f49ad10e87f4add5f08057e5c1cd0b45004f22b63f91787ad");
	X("9D40", "48ec88684d8239091d13d3d1d582a1b7cb07f6b67d9e9f1759c117f8dc447d012d6802748f1c613763a88e88a996a177ec562ba15c7da086502334f0df97d1b7");
	X("AA80", "635213e9c8ffb6a535e6eaae9e9231d901e07607afaecd9122e3dfbacb0f11fb388fcb91e68e1d7f05c70f1f8a5dd6549c93f87fb4f25fa31d6c6abb4b9a55c4");
	X("9830", "75d769e87d7c935faf58cd93043019bae5162e6b54d3b8b4aa2ae5fda3705e721e669dce33e8d59db6db0ad2c4ba7dc5f931ecf67a3448024b1515800b777129");
	X("5030", "8903efd089efa56634fa8d4bd953abcf30d72fca70ebad0ddfccbd4cda514c5679dc763291dbb888a0bc7af7964a3be07f14c37ee696b51099bd91466429b22b");
	X("4D24", "9464762c5824a83eef9445571734261e57a453e30e12e9581c4b378a7ec8219bb3f25b0d900aa8dd446f2788395e4216f539ec4d3f8d41090ae7951a43bdf2ed");
	X("CBDE", "ae69b3b57792c5909a8482a4006eccceeb14d1f76b15da66018586ae132adae8641890921c13bdc2164be991b1e248d66b5e647a8e4b4eef73e33d3f06a33a5c");
	X("41FB", "20afd72afbb66a5a0efd8b4a627cc2c82a5e4b6c63b0c9a78735c188d248c7588fb4ee566b3b6fdcc235a498f7263feb7ab1411582a7055e3ce7a8c976e61fcc");
	X("4FF400", "802ad11445c31e09a51f1431a9b735a009f631e192c78de140a484bfba91d5c5482a5539509f1b0fca92f4e5ab6040d1efdb7fe64f107b6cf5a5c79342c10491");
	X("FD0440", "0e1a3fdc9506b0fb96bd69a14149fa41484c035a4867cc8f9ae8704e7fbf5b24168089c1ae654a46d6dd2375bea3c62df92b2cba320a09a642917c7c7790f199");
	X("424D00", "dd05e2ca3219efe375f2bf8edb2f45c5c490fb5e06bddbb2a813e5e232c62f15b70324db66f442be5d2a437b21df736ebbd3eba0b58591550b45ef9838703054");
	X("3FDEE0", "8dc0a2797160f1eb1e4fca864f99298e655572adce432a03e5ff3a5dc814bbd81e3b328bbf8191e9041c57780f27fbecc1618b3fd140da3b96e2d0f769b441a1");
	X("335768", "b501b4abc63aed8c5841e691e7f5ff5b096637e19342fa44feb53ddf84f16eb8bc92730c41f2b29131f3c6701f9b3bb6dcb5af7e8a4d900243e7b136a0d60ddb");
	X("051E7C", "9d28c92c6b54f7f6888b6d210029eeafde05b7ab95e2a34d1f3979d3b62c8940c4980a1a46cfead4a630cf8e5efb521b5e412059786f626d1054e62b0f2ed916");
	X("717F8C", "855c53190122aec182624cd98ec4f97b362bc74c01eef9e1d140ce79ab54e1277e8b873df52585c420b8c6d99652b47e5de322225dc1792788e71aa2912861f8");
	X("1F877C", "b1211367fd8a886674f74d92716e7585f9b6e933edc5ee7f974facdccc481cfa42a0532375b94f2c0dd73d6189a815c2bafb5686d784be81fbb447b0f291272b");
	X("EB35CF80", "df4050f53c05fa145dd89bf9ac94dcfd81f96f984ca484dbbbf92259f7b8ae19d2fec657853bb2673ddb0ee26f298d8c4923daaeedc2926e7daf2157c697b2ed");
	X("B406C480", "f507a52fb135565c74e5905fe9a43dcbfb29b39344faec39c15ad09b0a465fef0be36183433d29243d74f119b8242bd94b0e6b37c2c1039d9d7c5af316fc46d4");
	X("CEE88040", "06228dc4e1b32e816c77273e5e5b66349e82f48c6c7f3eea8876efa5db32d9fcf2e26dd3eeae7355877ca9e7b31c0924c521b5e729cf08c4175dab8a451e5ad8");
	X("C584DB70", "fbbbc6cb4832c6545236f9e36fc92f7a7709e38fdf7ea6cb100048409a3c5f36e8a336360e7ab5ec26a8c13d8e663f08cac2b2519f40c61cd3284b9f320463da");
	X("53587BC8", "91f4c152a8f637247a1747e2ca4df130d3be99c2dc3a9f2991df7a60900b10931fe670d10dc7725dc30e068f3220575f033e8634dd58904ca3136a04158a42ed");
	X("69A305B0", "5068d281c4eef98502d0d1de51b1f78764059fb599f036fd7f60c0fd4f50b634205a196306ee78eabd3ce8eb8333a6da8bf0c7176d5230bcc6af48700fd7f343");
	X("C9375ECE", "3501607fa6b01de201a10bd1db756621cd2097e3476acf862e8b723d98bc439984f8de6bc8514ed800265ef21116cf36aba1f68f9f96befb9b48eafbe19bf805");
	X("C1ECFDFC", "ccbcdbc1a30ebbcc4fc015fdb1caba6c0ad6719301b4bbad4b0efab1141174a15e2e8b8b8e5671c1864a0f75ecb20f76dac45159e67786d07d79a29b1827e5a4");
	X("8D73E8A280", "1f41330d6ad6f6fafa54f7c1a698a03ebd96e74025d0e5476138589e02194c133fad988e47c81a0ed887943670d41e560327761f897d996dc59cb9025b095315");
	X("06F2522080", "4d9fa2dc0049230afd0d72e6195a19523d3d8b4f1983d1108157b7085ae82a0f90542351fc8d66437fc9a9bc6f98807313abdc2b4c6140b819b201df6c62b1da");
	X("3EF6C36F20", "cc14844fa038671773c4201fdd7e106e951d77cef951d253e9da9f07f2bb3040a2569834d6836b30b743d39bee94a7e7721672ca30fd94b1de23bdcb1c218ff5");
	X("0127A1D340", "37f909daa8a5e503b8af6f0826ba02ac14a4e92221a551cbcf4128a4c867d101d4f158232de31bc4d9ed298def8e202db9490a0da1d09cb665bdf18a14f8ff4a");
	X("6A6AB6C210", "4b6c339182ec57c24832313bba724aa37b2d8833e04fc31a1a869c3da3ba106136bfda897cec7aedd28227c2b118fa417c2592a71216be6e3766b26f04b4ea4d");
	X("AF3175E160", "04548a4bf2fd865da48c060262bf0f17dc084c9d4162a06f2f7aad1aed7244d7422d257e54a9eef9c24c8827e88fa707c9d0ee1ac555b46b7ee8e5ecc6fa8f1d");
	X("B66609ED86", "a5b8b8de6cf9c14ced277140d219755a4af5c80e0dbd67721831b1284a501c5092a669390ecf997e406c4c1a43b25903759d0ae5ac09390f5d2ed747ae1bd361");
	X("21F134AC57", "ec6eaabc2a128c38dfcddf9aaad5bb6fba397aac06a4b584b2dbdeb0cd7fdb1fd248ef93c0686b73818b2b78c923c70eba63c096f33d842ada959f7674e4730c");
	X("3DC2AADFFC80", "eb9dc2c740374e28d9247393afe2d713e843c289977ea48abda51fb2950c3967aea50d48e7eba75b591140062e14495d416934f9817ec832988397c3a781dfeb");
	X("9202736D2240", "0c5dfdfd3167a6ca86abf804e71342e893b0270b3ef2d4c81032482538c0f5802817a16d6ec12f541ce947d5579c27b9b7a5ee424554f3fa2c78a2fa8340d444");
	X("F219BD629820", "40f191621e6a183a0bd3f10df6716ddf09339fba20b48dbbb09fb44b82f15be77ad595bfdd1f1245b930334ea7042e716626d5fb49bc275df0b60639d9aea618");
	X("F3511EE2C4B0", "e76cefbc4621956af8d7d5121bd10bdddaeff359ff2b988425f22bba15c8ad4dbbf70f7e8b5cf2ee044eb9625bf36ec9f910e01701bbc8541d8529a13a56cc98");
	X("3ECAB6BF7720", "39b3d2f730b774e16504fd6e5b2eafca5f68c9d5022e62d3bca67793d3260f34d1dd594b95ef5a735aa9b78ff0b6028b484c34a4bcd9adb4ec5a9736ecd434eb");
	X("CD62F688F498", "69b151653d645e84c6eb509665a89a075210f743f8c7218e6c98895c9436e9eedfa2094597b13533e1c3af6b21907ddf2f4c5c8379e64a71b66add2a170d5689");
	X("C2CBAA33A9F8", "eac8acd05f04461d8050b53dafa99b0516adfacc8dbd3adc7dacfc7adea4ad9250fa9e10ad43602e15a762a333a2cdb1c040ede1de79ac51b484507b5ae16536");
	X("C6F50BB74E29", "b6e8a7380df1f007d7c271e7255bbca7714f25029ac1fd6fe92ef74cbcd9e99c112f8ae1a45ccb566ce19d9678a122c612beff5f8eeeee3f3f402fd2781182d4");
	X("79F1B4CCC62A00", "1cc9fe09100fbc45f20382353785aa753fbd19ea0ab655c0d8338e0d07154ccaa5659698a6627302c25dd54cdfde00c0ef06905abc55030563399ca8efae2c22");
#undef X

	return failed;
}

static const char *
digest_blake2s(int length, const void *msg, size_t msglen)
{
	static char hex[1025];
	unsigned char buf[512];
	size_t req;
	char *data;
	struct libblake_blake2s_state s;
	struct libblake_blake2s_params params;

	memset(&params, 0, sizeof(params));
	params.digest_len = (uint_least8_t)(length / 8);
	params.fanout = 1;
	params.depth = 1;

	req = libblake_blake2s_digest_get_required_input_size(msglen);
	data = malloc(req);
	memcpy(data, msg, msglen);
	libblake_blake2s_init(&s, &params, NULL);
	libblake_blake2s_digest(&s, data, msglen, 0, (size_t)length / 8, buf);
	libblake_encode_hex(buf, (size_t)length / 8, hex, 0);
	free(data);

	return hex;
}

#define CHECK_BLAKE2S_STR(LENGTH, MSG, EXPECTED)\
	failed |= !check_blake2s_(LENGTH, "“"MSG"”", MSG, sizeof(MSG) - 1, EXPECTED)
#define CHECK_BLAKE2S_224_STR(MSG, EXPECTED) CHECK_BLAKE2S_STR(224, MSG, EXPECTED)
#define CHECK_BLAKE2S_256_STR(MSG, EXPECTED) CHECK_BLAKE2S_STR(256, MSG, EXPECTED)

#if 0
# define CHECK_BLAKE2S_HEX(LENGTH, MSG, EXPECTED)\
	failed |= !check_blake2s_(LENGTH, "0x"MSG, buf, libblake_decode_hex(MSG, SIZE_MAX, buf, &(int){0}), EXPECTED)
# define CHECK_BLAKE2S_224_HEX(MSG, EXPECTED) CHECK_BLAKE2S_HEX(224, MSG, EXPECTED)
# define CHECK_BLAKE2S_256_HEX(MSG, EXPECTED) CHECK_BLAKE2S_HEX(256, MSG, EXPECTED)
#endif

static int
check_blake2s_(int length, const char *dispmsg, const void *msg, size_t msglen, const char *expected)
{
	const char *result;
	result = digest_blake2s(length, msg, msglen);
	if (strcasecmp(result, expected)) {
		fprintf(stderr, "BLAKE2s-%i failed for %s:\n", length, dispmsg);
		fprintf(stderr, "\tResult:   %s\n", result);
		fprintf(stderr, "\tExpected: %s\n", expected);
		fprintf(stderr, "\n");
		return 0;
	}
	return 1;
}

static int
check_blake2s(void)
{
#if 0
	char buf[1025];
#endif
	int failed = 0;

	CHECK_BLAKE2S_224_STR("", "1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4");
	CHECK_BLAKE2S_256_STR("", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
	/* TODO need more tests for BLAKE2s */

	return failed;
}

static const char *
digest_blake2b(int length, const void *msg, size_t msglen)
{
	static char hex[1025];
	unsigned char buf[512];
	size_t req;
	char *data;
	struct libblake_blake2b_state s;
	struct libblake_blake2b_params params;

	memset(&params, 0, sizeof(params));
	params.digest_len = (uint_least8_t)(length / 8);
	params.fanout = 1;
	params.depth = 1;

	req = libblake_blake2b_digest_get_required_input_size(msglen);
	data = malloc(req);
	memcpy(data, msg, msglen);
	libblake_blake2b_init(&s, &params, NULL);
	libblake_blake2b_digest(&s, data, msglen, 0, (size_t)length / 8, buf);
	libblake_encode_hex(buf, (size_t)length / 8, hex, 0);
	free(data);

	return hex;
}

#define CHECK_BLAKE2B_STR(LENGTH, MSG, EXPECTED)\
	failed |= !check_blake2b_(LENGTH, "“"MSG"”", MSG, sizeof(MSG) - 1, EXPECTED)
#define CHECK_BLAKE2B_384_STR(MSG, EXPECTED) CHECK_BLAKE2B_STR(384, MSG, EXPECTED)
#define CHECK_BLAKE2B_512_STR(MSG, EXPECTED) CHECK_BLAKE2B_STR(512, MSG, EXPECTED)

#if 0
# define CHECK_BLAKE2B_HEX(LENGTH, MSG, EXPECTED)\
	failed |= !check_blake2b_(LENGTH, "0x"MSG, buf, libblake_decode_hex(MSG, SIZE_MAX, buf, &(int){0}), EXPECTED)
# define CHECK_BLAKE2B_384_HEX(MSG, EXPECTED) CHECK_BLAKE2B_HEX(384, MSG, EXPECTED)
# define CHECK_BLAKE2B_512_HEX(MSG, EXPECTED) CHECK_BLAKE2B_HEX(512, MSG, EXPECTED)
#endif

static int
check_blake2b_(int length, const char *dispmsg, const void *msg, size_t msglen, const char *expected)
{
	const char *result;
	result = digest_blake2b(length, msg, msglen);
	if (strcasecmp(result, expected)) {
		fprintf(stderr, "BLAKE2b-%i failed for %s:\n", length, dispmsg);
		fprintf(stderr, "\tResult:   %s\n", result);
		fprintf(stderr, "\tExpected: %s\n", expected);
		fprintf(stderr, "\n");
		return 0;
	}
	return 1;
}

static int
check_blake2b(void)
{
#if 0
	char buf[1025];
#endif
	int failed = 0;

	CHECK_BLAKE2B_384_STR("", "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100");
	CHECK_BLAKE2B_512_STR("", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");

	CHECK_BLAKE2B_512_STR("The quick brown fox jumps over the lazy dog",
	                      "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918");

	CHECK_BLAKE2B_512_STR("The quick brown fox jumps over the lazy dof",
	                      "ab6b007747d8068c02e25a6008db8a77c218d94f3b40d2291a7dc8a62090a744c082ea27af01521a102e42f480a31e9844053f456b4b41e8aa78bbe5c12957bb");
	/* TODO need more tests for BLAKE2b */

	return failed;
}

int
main(void)
{
	int failed = 0;

	CHECK_HEX(1, 00, 12, 32, 00, 45, 67, 82, 9A, B0, CD, FE, FF, 80, 08, CC, 28);
	CHECK_HEX(0, 00, 12, 32, 00, 45, 67, 82, 9a, b0, cd, fe, ff, 80, 08, cc, 28);

	failed |= check_blake1();
	failed |= check_blake2s();
	failed |= check_blake2b();
	/* TODO need tests for BLAKE2Xs */
	/* TODO need tests for BLAKE2Xb */

	return failed;
}

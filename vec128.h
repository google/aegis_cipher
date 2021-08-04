// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#if defined(__SSE2__) && defined(__AES__)
#include "vec128_x86_intrinsics.h"
#elif defined(__ARM_NEON) && defined(__ARM_FEATURE_CRYPTO)
#include "vec128_neon_intrinsics.h"
#elif defined(__ALTIVEC__)
#include "vec128_ppc_intrinsics.h"
#else
#error No supported Vec128 implementation found.
#endif

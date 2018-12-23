//
// Copyright (C) 2018 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <bfdebug.h>
#include <domain/domain.h>

namespace hyperkernel
{

domain::domain(domainid_type domainid) :
    m_id{domainid}
{ }

void
domain::run(bfobject *obj)
{ bfignored(obj); }

void
domain::hlt(bfobject *obj)
{ bfignored(obj); }

void
domain::init(bfobject *obj)
{ bfignored(obj); }

void
domain::fini(bfobject *obj)
{ bfignored(obj); }

domain::domainid_type
domain::id() const noexcept
{ return m_id; }

void
domain::set_entry(uint64_t gpa) noexcept
{ m_entry = gpa; }

uint64_t
domain::entry() const noexcept
{ return m_entry; }

}

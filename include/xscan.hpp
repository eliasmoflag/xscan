#pragma once
#include <vector>
#include <string>
#include <type_traits>

namespace xscan {
    namespace detail {
        struct image_dos_header {
            std::uint16_t e_magic;
            std::uint16_t e_cblp;
            std::uint16_t e_cp;
            std::uint16_t e_crlc;
            std::uint16_t e_cparhdr;
            std::uint16_t e_minalloc;
            std::uint16_t e_maxalloc;
            std::uint16_t e_ss;
            std::uint16_t e_sp;
            std::uint16_t e_csum;
            std::uint16_t e_ip;
            std::uint16_t e_cs;
            std::uint16_t e_lfarlc;
            std::uint16_t e_ovno;
            std::uint16_t e_res[4];
            std::uint16_t e_oemid;
            std::uint16_t e_oeminfo;
            std::uint16_t e_res2[10];
            std::int32_t e_lfanew;
        };

        struct image_file_header {
            std::uint16_t Machine;
            std::uint16_t NumberOfSections;
            std::uint32_t TimeDateStamp;
            std::uint32_t PointerToSymbolTable;
            std::uint32_t NumberOfSymbols;
            std::uint16_t SizeOfOptionalHeader;
            std::uint16_t Characteristics;
        };

        struct image_nt_headers {
            std::uint32_t Signature;
            image_file_header FileHeader;
        };

        constexpr auto image_sizeof_short_name = 8;
        constexpr auto image_scn_mem_execute = 0x20000000;

        struct image_section_header {
            std::uint8_t Name[image_sizeof_short_name];
            union {
                std::uint32_t PhysicalAddress;
                std::uint32_t VirtualSize;
            } Misc;
            std::uint32_t VirtualAddress;
            std::uint32_t SizeOfRawData;
            std::uint32_t PointerToRawData;
            std::uint32_t PointerToRelocations;
            std::uint32_t PointerToLinenumbers;
            std::uint16_t NumberOfRelocations;
            std::uint16_t NumberOfLinenumbers;
            std::uint32_t Characteristics;
        };

        constexpr bool is_xdigit(char c) {
            return (c >= '0' && c <= '9')
                or (c >= 'A' && c <= 'F')
                or (c >= 'a' && c <= 'f');
        }

        constexpr std::uint8_t xdigit(char c) {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }
            else if (c >= 'A' && c <= 'F') {
                return c + 10 - 'A';
            }
            else if (c >= 'a' && c <= 'f') {
                return c + 10 - 'a';
            }
            return 0;
        }
    }

    using address_range = std::pair<const std::uint8_t*, const std::uint8_t*>;

    class pe_sections {
    public:
        inline pe_sections(const void* image_base) {

            const auto module_data{ reinterpret_cast<const std::uint8_t*>(image_base) };
            const auto dos_header{ reinterpret_cast<const detail::image_dos_header*>(module_data) };
            const auto nt_headers{ reinterpret_cast<const detail::image_nt_headers*>(module_data + dos_header->e_lfanew) };

            for (std::uint16_t i{ 0 }; i < nt_headers->FileHeader.NumberOfSections; i++) {

                const auto& section{
                    reinterpret_cast<const detail::image_section_header*>(
                        reinterpret_cast<std::uintptr_t>(&nt_headers->FileHeader)
                        + sizeof(detail::image_nt_headers::FileHeader)
                        + nt_headers->FileHeader.SizeOfOptionalHeader
                    )[i]
                };

                if (!(section.Characteristics & detail::image_scn_mem_execute)) {
                    continue;
                }

                const auto section_begin{ module_data + section.VirtualAddress };
                const auto section_end{ section_begin + section.Misc.VirtualSize };

                m_ranges.emplace_back(section_begin, section_end);
            }
        }

        constexpr auto begin() const {
            return m_ranges.begin();
        }

        constexpr auto end() const {
            return m_ranges.end();
        }

    protected:
        std::vector<address_range> m_ranges;
    };

    class cursor {
    public:
        inline cursor(const void* address = 0)
            : m_address(reinterpret_cast<const std::uint8_t*>(address)) {}

        template<typename type>
            requires std::is_integral_v<type>
        inline cursor add(type value) const {
            return cursor(m_address + value);
        }

        template<typename type>
            requires std::is_integral_v<type>
        inline cursor sub(type value) const {
            return cursor(m_address + value);
        }

        inline cursor deref() const {
            return cursor(*reinterpret_cast<void* const*>(m_address));
        }

        inline cursor rip() const {
            return cursor(m_address + sizeof(std::int32_t) + *reinterpret_cast<const std::int32_t*>(m_address));
        }

        template<typename type>
        inline type as() const {
            return type(m_address);
        }

        template<typename type>
        inline operator type() const {
            return this->as<type>();
        }

    protected:
        const std::uint8_t* m_address;
    };

    class pattern {
    public:
        inline pattern(std::string_view pattern) {
            const auto begin{ const_cast<char*>(pattern.data()) };
            const auto end{ begin + pattern.size() };

            for (auto current{ begin }; current < end;) {

                if (*current == '?') {
                    while (++current < end && *current == '?');
                    m_bytes.push_back(-1);
                }
                else if (current + 1 < end
                    && detail::is_xdigit(current[0])
                    && detail::is_xdigit(current[1])) {

                    m_bytes.push_back((detail::xdigit(current[0]) << 4) | detail::xdigit(current[1]));
                    current += 2;
                }
                else {
                    ++current;
                }
            }
        }

        inline cursor scan(const address_range& ranges) const {

            const auto byte_count{ m_bytes.size() };
            for (auto it{ ranges.first }; it != ranges.second - byte_count; ++it) {

                for (std::size_t i{ 0 }; true; ) {

                    if (m_bytes[i] != -1 && it[i] != m_bytes[i]) {
                        break;
                    }

                    if (++i == byte_count) {
                        return it;
                    }
                }
            }

            return nullptr;
        }

        template<typename ranges>
        inline cursor scan(const ranges& range) const {
            for (const auto& addr_range : range) {
                if (const auto match{ this->scan(addr_range) }) {
                    return match;
                }
            }
            return nullptr;
        }

    protected:
        std::vector<std::int32_t> m_bytes;
    };
}

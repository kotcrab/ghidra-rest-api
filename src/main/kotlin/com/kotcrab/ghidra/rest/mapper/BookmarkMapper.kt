package com.kotcrab.ghidra.rest.mapper

import com.kotcrab.ghidra.rest.model.ApiBookmark
import ghidra.program.model.listing.BookmarkManager

class BookmarkMapper {
  fun map(bookmarkManager: BookmarkManager): List<ApiBookmark> {
    return bookmarkManager.bookmarksIterator.asSequence()
      .map {
        ApiBookmark(
          id = it.id,
          address = it.address.offsetAsBigInteger,
          type = it.typeString,
          category = it.category,
          comment = it.comment,
        )
      }
      .toList()
  }
}

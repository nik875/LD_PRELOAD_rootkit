#ifndef HIDE_PROCESS_H
#define HIDE_PROCESS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the hide_process library.
 * This is called automatically via constructor, but can be called explicitly.
 * 
 * Returns: 0 on success, -1 on failure
 */
int hide_process_init(void);

/**
 * Add a keyword to the list of strings to conceal.
 * Any process cmdline or filename containing this keyword will be hidden.
 * 
 * @param keyword: The string to hide (will be copied internally)
 * Returns: 0 on success, -1 on failure
 */
int hide_process_add_keyword(const char *keyword);

/**
 * Remove a keyword from the list of strings to conceal.
 * 
 * @param keyword: The exact string to remove
 * Returns: 0 on success (or if keyword wasn't found), -1 on failure
 */
int hide_process_remove_keyword(const char *keyword);

/**
 * Remove all keywords from the list.
 * 
 * Returns: 0 on success, -1 on failure
 */
int hide_process_clear_keywords(void);

/**
 * Get a copy of the current keyword list.
 * Caller must free both the array and each string inside it.
 * 
 * @param keywords: Output pointer to array of strings
 * @param count: Output pointer to number of keywords
 * Returns: 0 on success, -1 on failure
 */
int hide_process_list_keywords(char ***keywords, int *count);

/**
 * Enable or disable debug logging to stderr.
 * 
 * @param enabled: 1 to enable, 0 to disable
 */
void hide_process_set_debug(int enabled);

#ifdef __cplusplus
}
#endif

#endif /* HIDE_PROCESS_H */
